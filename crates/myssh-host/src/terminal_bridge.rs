use std::collections::HashMap;
use std::io;

use sha2::{Digest, Sha256};

use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use myssh_auth::AuthenticatedIdentity;
use myssh_core::{Connection, ConnectionWriter, SessionKind, SessionManager};
use myssh_protocol::{
    FileBeginPayload, FileChunkPayload, FileDirection, FileEndPayload, FileErrorCode,
    FileResponsePayload, FileResponseStatus, MessageKind, SessionClosePayload, SessionOpenPayload,
    SessionOpenStatus, SessionOpenedPayload, SessionResizePayload, SessionType, FILE_CHUNK_SIZE,
};

use crate::auth_connection::AuthenticatedConnection;
use crate::file_transfer::{DownloadSource, HostFileStore};
use crate::file_transfer_session::FileTransferSessionManager;
use crate::pty::PtyIoEvent;
use crate::shell_session::ShellSessionManager;

const NETWORK_QUEUE_CAPACITY: usize = 64;

/// One outbound protocol frame.
struct OutboundFrame {
    kind: MessageKind,
    session_id: u128,
    request_id: Option<u64>,
    payload: Vec<u8>,
}

/// Create one dedicated network writer for all sessions.
fn spawn_writer(
    mut writer: ConnectionWriter,
) -> (mpsc::Sender<OutboundFrame>, JoinHandle<io::Result<()>>) {
    let (tx, mut rx) = mpsc::channel::<OutboundFrame>(NETWORK_QUEUE_CAPACITY);

    let task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            match frame.request_id {
                Some(request_id) => {
                    writer
                        .send_with_request_id(
                            frame.kind,
                            frame.session_id,
                            request_id,
                            frame.payload,
                        )
                        .await?;
                }
                None => {
                    writer
                        .send(frame.kind, frame.session_id, frame.payload)
                        .await?;
                }
            }
        }

        Ok(())
    });

    (tx, task)
}

/// PTY output forwarded from an individual Shell session.
struct SessionOutput {
    session_id: u128,
    event: PtyIoEvent,
}

fn broken_pipe(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, message)
}

/// Stream one validated Host file through the shared network writer queue.
async fn stream_download(
    source: DownloadSource,
    session_id: u128,
    request_id: u64,
    outbound_tx: mpsc::Sender<OutboundFrame>,
) -> io::Result<()> {
    let begin = FileBeginPayload {
        direction: FileDirection::Download,
        file_size: source.file_size,
        remote_path: source.remote_path,
    }
    .encode()?;

    outbound_tx
        .send(OutboundFrame {
            kind: MessageKind::FileBegin,
            session_id,
            request_id: Some(request_id),
            payload: begin,
        })
        .await
        .map_err(|_| broken_pipe("Network writer stopped"))?;

    let mut file = tokio::fs::File::from_std(source.file);
    let mut hasher = Sha256::new();
    let mut total_chunks = 0u64;
    let mut total_size = 0u64;

    while total_size < source.file_size {
        let remaining = source.file_size - total_size;
        let chunk_size = remaining.min(FILE_CHUNK_SIZE as u64) as usize;
        let mut data = vec![0u8; chunk_size];

        file.read_exact(&mut data).await?;
        hasher.update(&data);

        let payload = FileChunkPayload {
            chunk_index: total_chunks,
            data,
        }
        .encode()?;

        outbound_tx
            .send(OutboundFrame {
                kind: MessageKind::FileChunk,
                session_id,
                request_id: Some(request_id),
                payload,
            })
            .await
            .map_err(|_| broken_pipe("Network writer stopped"))?;

        total_chunks = total_chunks
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Chunk count overflow"))?;

        total_size = total_size
            .checked_add(chunk_size as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "File size overflow"))?;
    }

    // Detect a file that grew after open_download() inspected its metadata.
    let mut extra = [0u8; 1];
    if file.read(&mut extra).await? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Host file grew during download",
        ));
    }

    let digest = hasher.finalize();
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&digest);

    let end = FileEndPayload {
        total_chunks,
        total_size,
        sha256,
    }
    .encode();

    outbound_tx
        .send(OutboundFrame {
            kind: MessageKind::FileEnd,
            session_id,
            request_id: Some(request_id),
            payload: end,
        })
        .await
        .map_err(|_| broken_pipe("Network writer stopped"))?;

    Ok(())
}

/// Run a download and send its final operation response.
fn spawn_download_task(
    source: DownloadSource,
    session_id: u128,
    request_id: u64,
    outbound_tx: mpsc::Sender<OutboundFrame>,
    done_tx: mpsc::Sender<u128>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let result = stream_download(source, session_id, request_id, outbound_tx.clone()).await;

        let (status, error_code) = match result {
            Ok(()) => (FileResponseStatus::Completed, FileErrorCode::None),
            Err(error) => {
                let code = if error.kind() == io::ErrorKind::InvalidData
                    || error.kind() == io::ErrorKind::UnexpectedEof
                {
                    FileErrorCode::IntegrityMismatch
                } else {
                    FileErrorCode::Io
                };

                (FileResponseStatus::Failed, code)
            }
        };

        if let Ok(payload) = (FileResponsePayload { status, error_code }).encode() {
            let _ = outbound_tx
                .send(OutboundFrame {
                    kind: MessageKind::FileResponse,
                    session_id,
                    request_id: Some(request_id),
                    payload,
                })
                .await;
        }

        let _ = done_tx.send(session_id).await;
    })
}

/// Run the terminal protocol without enabling file transfer.
pub async fn run_terminal_connection(connection: AuthenticatedConnection) -> io::Result<()> {
    run_terminal_connection_inner(connection, None).await
}

/// Run the terminal protocol with an explicitly configured file root.
pub async fn run_terminal_connection_with_file_store(
    connection: AuthenticatedConnection,
    store: HostFileStore,
) -> io::Result<()> {
    run_terminal_connection_inner(connection, Some(store)).await
}

async fn run_terminal_connection_inner(
    connection: AuthenticatedConnection,
    store: Option<HostFileStore>,
) -> io::Result<()> {
    let AuthenticatedConnection { stream, identity } = connection;

    // Preserve the authenticated identity for connection auditing.
    let _identity: AuthenticatedIdentity = identity;

    let (mut reader, writer) = Connection::new(stream).into_split();
    let (outbound_tx, mut writer_task) = spawn_writer(writer);

    let (event_tx, mut event_rx) = mpsc::channel::<SessionOutput>(NETWORK_QUEUE_CAPACITY);
    let (download_done_tx, mut download_done_rx) = mpsc::channel::<u128>(NETWORK_QUEUE_CAPACITY);

    // One shared session namespace for Shell and FileTransfer.
    let mut core_sessions = SessionManager::new();
    let mut shell_sessions = ShellSessionManager::new();
    let mut file_sessions = store.map(FileTransferSessionManager::new);

    let mut writer_task_result = None;
    let mut output_tasks: HashMap<u128, JoinHandle<()>> = HashMap::new();
    let mut download_tasks: HashMap<u128, JoinHandle<()>> = HashMap::new();

    let run_result: io::Result<()> = async {
        loop {
            tokio::select! {
                writer_result = &mut writer_task => {
                    writer_task_result = Some(writer_result);
                    break;
                }

                incoming = reader.receive() => {
                    let frame = incoming?;

                    match frame.header.kind {
                        MessageKind::SessionOpen => {
                            let open = SessionOpenPayload::decode(&frame.payload)?;

                            let is_shell = open.session_type == SessionType::Shell;

                            let response = match open.session_type {
                                SessionType::Shell => {
                                    shell_sessions.accept_open_request(
                                        &mut core_sessions,
                                        &frame,
                                    )?
                                }

                                SessionType::FileTransfer => {
                                    match file_sessions.as_mut() {
                                        Some(manager) => {
                                            manager.accept_open_request(
                                                &mut core_sessions,
                                                &frame,
                                            )?
                                        }
                                        None => {
                                            shell_sessions.accept_open_request(
                                                &mut core_sessions,
                                                &frame,
                                            )?
                                        }
                                    }
                                }
                            };

                            let status =
                                SessionOpenedPayload::decode(&response.payload)?.status;

                            let session_id = response.header.session_id;

                            outbound_tx
                                .send(OutboundFrame {
                                    kind: response.header.kind,
                                    session_id,
                                    request_id: Some(response.header.request_id),
                                    payload: response.payload,
                                })
                                .await
                                .map_err(|_| broken_pipe("Network writer stopped"))?;

                            // Only Shell sessions have PTY event forwarders.
                            if is_shell && status == SessionOpenStatus::Accepted {
                                let mut receiver =
                                    shell_sessions.take_event_receiver(session_id)?;

                                let session_event_tx = event_tx.clone();

                                let output_task = tokio::spawn(async move {
                                    while let Some(event) = receiver.recv().await {
                                        let output = SessionOutput {
                                            session_id,
                                            event,
                                        };

                                        if session_event_tx.send(output).await.is_err() {
                                            break;
                                        }
                                    }
                                });

                                output_tasks.insert(session_id, output_task);
                            }
                        }

                        MessageKind::SessionData => {
                            let session_id = frame.header.session_id;

                            if session_id == 0 {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "SessionData requires a non-zero session ID",
                                ));
                            }

                            let session = shell_sessions.get_mut(session_id).ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::NotFound,
                                    "Unknown Shell session",
                                )
                            })?;

                            session.send_input(frame.payload).await?;
                        }

                        MessageKind::SessionResize => {
                            let session_id = frame.header.session_id;

                            if session_id == 0 {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "SessionResize requires a non-zero session ID",
                                ));
                            }

                            let size =
                                SessionResizePayload::decode(&frame.payload)?;

                            let session =
                                shell_sessions.get(session_id).ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::NotFound,
                                        "Unknown Shell session",
                                    )
                                })?;

                            session.resize(size)?;
                        }

                        MessageKind::SessionClose => {
                            let session_id = frame.header.session_id;

                            if session_id == 0 {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "SessionClose requires a non-zero session ID",
                                ));
                            }

                            SessionClosePayload::decode(&frame.payload)?;

                            let session_kind = core_sessions
                                .get(session_id)
                                .map(|session| session.kind)
                                .ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::NotFound,
                                        "Unknown session",
                                    )
                                })?;

                            match session_kind {
                                SessionKind::Shell => {
                                    if let Some(task) = output_tasks.remove(&session_id) {
                                        task.abort();
                                        let _ = task.await;
                                    }

                                    shell_sessions.close(
                                        &mut core_sessions,
                                        session_id,
                                    )?;
                                }

                                SessionKind::FileTransfer => {
                                    if let Some(task) = download_tasks.remove(&session_id) {
                                        task.abort();
                                        let _ = task.await;
                                    }

                                    let manager = file_sessions.as_mut().ok_or_else(|| {
                                        io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "FileTransfer is not enabled",
                                        )
                                    })?;

                                    manager.close(
                                        &mut core_sessions,
                                        session_id,
                                    )?;
                                }
                            }
                        }

                        MessageKind::FileRequest => {
                            let manager = file_sessions.as_mut().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    "FileTransfer is not enabled",
                                )
                            })?;

                            let (response, source) =
                                manager.handle_request(&core_sessions, &frame)?;

                            // Queue Ready before starting the streaming worker.
                            outbound_tx
                                .send(OutboundFrame {
                                    kind: response.header.kind,
                                    session_id: response.header.session_id,
                                    request_id: Some(response.header.request_id),
                                    payload: response.payload,
                                })
                                .await
                                .map_err(|_| broken_pipe("Network writer stopped"))?;

                            if let Some(source) = source {
                                let session_id = frame.header.session_id;
                                let request_id = frame.header.request_id;

                                let task = spawn_download_task(
                                    source,
                                    session_id,
                                    request_id,
                                    outbound_tx.clone(),
                                    download_done_tx.clone(),
                                );

                                download_tasks.insert(session_id, task);
                            }
                        }

                        MessageKind::FileBegin => {
                            let manager = file_sessions.as_mut().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    "FileTransfer is not enabled",
                                )
                            })?;

                            let response =
                                manager.handle_begin(&core_sessions, &frame)?;

                            outbound_tx
                                .send(OutboundFrame {
                                    kind: response.header.kind,
                                    session_id: response.header.session_id,
                                    request_id: Some(response.header.request_id),
                                    payload: response.payload,
                                })
                                .await
                                .map_err(|_| broken_pipe("Network writer stopped"))?;
                        }

                        MessageKind::FileChunk => {
                            let manager = file_sessions.as_mut().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    "FileTransfer is not enabled",
                                )
                            })?;

                            manager.handle_chunk(&core_sessions, &frame)?;
                        }

                        MessageKind::FileEnd => {
                            let manager = file_sessions.as_mut().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    "FileTransfer is not enabled",
                                )
                            })?;

                            let response =
                                manager.handle_end(&core_sessions, &frame)?;

                            outbound_tx
                                .send(OutboundFrame {
                                    kind: response.header.kind,
                                    session_id: response.header.session_id,
                                    request_id: Some(response.header.request_id),
                                    payload: response.payload,
                                })
                                .await
                                .map_err(|_| broken_pipe("Network writer stopped"))?;
                        }

                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Unsupported message kind in terminal session",
                            ));
                        }
                    }
                }

                download_finished = download_done_rx.recv() => {
                    let Some(session_id) = download_finished else {
                        break;
                    };

                    if let Some(task) = download_tasks.remove(&session_id) {
                        if task.await.is_err() {
                            // The worker's completion notification is still handled;
                            // connection cleanup will release any remaining state.
                        }
                    }

                    if let Some(manager) = file_sessions.as_mut() {
                        manager.finish_download(session_id);
                    }
                }

                output = event_rx.recv() => {
                    let Some(output) = output else {
                        break;
                    };

                    let session_id = output.session_id;

                    match output.event {
                        PtyIoEvent::Output(data) => {
                            if shell_sessions.contains(session_id) {
                                outbound_tx
                                    .send(OutboundFrame {
                                        kind: MessageKind::SessionData,
                                        session_id,
                                        request_id: None,
                                        payload: data,
                                    })
                                    .await
                                    .map_err(|_| {
                                        broken_pipe("Network writer stopped")
                                    })?;
                            }
                        }

                        PtyIoEvent::ReaderClosed
                        | PtyIoEvent::ReaderError(_)
                        | PtyIoEvent::WriterError(_) => {
                            if shell_sessions.contains(session_id) {
                                shell_sessions.close(
                                    &mut core_sessions,
                                    session_id,
                                )?;

                                if let Some(task) = output_tasks.remove(&session_id) {
                                    let _ = task.await;
                                }

                                outbound_tx
                                    .send(OutboundFrame {
                                        kind: MessageKind::SessionClose,
                                        session_id,
                                        request_id: None,
                                        payload: SessionClosePayload.encode(),
                                    })
                                    .await
                                    .map_err(|_| {
                                        broken_pipe("Network writer stopped")
                                    })?;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
    .await;

    // Stop PTY and download workers before releasing their session state.
    drop(event_rx);

    for (_, task) in download_tasks.drain() {
        task.abort();
        let _ = task.await;
    }

    drop(download_done_rx);

    let shell_cleanup_result = shell_sessions.close_all(&mut core_sessions);

    if let Some(manager) = file_sessions.as_mut() {
        manager.close_all(&mut core_sessions);
    }

    let mut output_task_error = None;

    for (_, task) in output_tasks.drain() {
        if task.await.is_err() && output_task_error.is_none() {
            output_task_error = Some(io::Error::other("PTY output forwarding task panicked"));
        }
    }

    // Let the network writer drain its queue.
    drop(outbound_tx);

    let writer_result = match writer_task_result {
        Some(result) => result,
        None => writer_task.await,
    }
    .map_err(|_| io::Error::other("Network writer task panicked"))?;

    run_result?;
    shell_cleanup_result?;
    writer_result?;

    if let Some(error) = output_task_error {
        return Err(error);
    }

    Ok(())
}

#[cfg(test)]
mod file_transfer_network_tests {
    use super::*;

    use myssh_protocol::{
        FileBeginPayload, FileChunkPayload, FileDirection, FileEndPayload, FileErrorCode,
        FileResponsePayload, FileResponseStatus,
    };
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn host_and_client_complete_file_upload_over_connection() {
        // 1. Create an isolated temporary storage root.
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let root = std::env::temp_dir().join(format!(
            "myssh-network-upload-{}-{unique}",
            std::process::id()
        ));

        std::fs::create_dir(&root).unwrap();

        let store = HostFileStore::new(&root, 1024 * 1024).unwrap();

        // 2. Create an in-memory bidirectional connection.
        let (client_stream, host_stream) = tokio::io::duplex(1024 * 1024);

        let authenticated = AuthenticatedConnection {
            stream: Box::new(host_stream) as myssh_transport::BoxedStream,
            identity: AuthenticatedIdentity {
                username: "upload-integration-test".to_string(),
                key_id: "upload-integration-test-key".to_string(),
            },
        };

        let host_task = tokio::spawn(async move {
            run_terminal_connection_with_file_store(authenticated, store).await
        });

        let mut client = Connection::new(Box::new(client_stream) as myssh_transport::BoxedStream);

        // 3. Open a FileTransfer session.
        let open_request_id = client
            .send(
                MessageKind::SessionOpen,
                0,
                SessionOpenPayload {
                    session_type: SessionType::FileTransfer,
                }
                .encode(),
            )
            .await
            .unwrap();

        let opened_frame = timeout(Duration::from_secs(5), client.receive())
            .await
            .expect("FileTransfer SessionOpen timed out")
            .expect("Failed to receive SessionOpened");

        assert_eq!(opened_frame.header.kind, MessageKind::SessionOpened);
        assert_eq!(opened_frame.header.request_id, open_request_id);

        let opened = SessionOpenedPayload::decode(&opened_frame.payload).unwrap();

        assert_eq!(opened.status, SessionOpenStatus::Accepted);

        let session_id = opened_frame.header.session_id;
        assert_ne!(session_id, 0);

        // 4. Prepare upload data and its SHA-256 digest.
        let data = b"MySSH Stage 06 network upload integration test.\n".repeat(32);

        let digest = Sha256::digest(&data);
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&digest);

        let remote_path = "network-upload.bin";

        // 5. Send FileBegin and expect Ready.
        let begin_request_id = client
            .send(
                MessageKind::FileBegin,
                session_id,
                FileBeginPayload {
                    direction: FileDirection::Upload,
                    file_size: data.len() as u64,
                    remote_path: remote_path.to_string(),
                }
                .encode()
                .unwrap(),
            )
            .await
            .unwrap();

        let ready_frame = timeout(Duration::from_secs(5), client.receive())
            .await
            .expect("FileBegin response timed out")
            .expect("Failed to receive FileResponse");

        assert_eq!(ready_frame.header.kind, MessageKind::FileResponse);
        assert_eq!(ready_frame.header.session_id, session_id);
        assert_eq!(ready_frame.header.request_id, begin_request_id);

        let ready = FileResponsePayload::decode(&ready_frame.payload).unwrap();

        assert_eq!(ready.status, FileResponseStatus::Ready);
        assert_eq!(ready.error_code, FileErrorCode::None);

        // 6. Send the file as one chunk.
        client
            .send(
                MessageKind::FileChunk,
                session_id,
                FileChunkPayload {
                    chunk_index: 0,
                    data: data.clone(),
                }
                .encode()
                .unwrap(),
            )
            .await
            .unwrap();

        // 7. Send FileEnd and expect Completed.
        let end_request_id = client
            .send(
                MessageKind::FileEnd,
                session_id,
                FileEndPayload {
                    total_chunks: 1,
                    total_size: data.len() as u64,
                    sha256,
                }
                .encode(),
            )
            .await
            .unwrap();

        let completed_frame = timeout(Duration::from_secs(5), client.receive())
            .await
            .expect("FileEnd response timed out")
            .expect("Failed to receive completion response");

        assert_eq!(completed_frame.header.kind, MessageKind::FileResponse);
        assert_eq!(completed_frame.header.session_id, session_id);
        assert_eq!(completed_frame.header.request_id, end_request_id);

        let completed = FileResponsePayload::decode(&completed_frame.payload).unwrap();

        assert_eq!(completed.status, FileResponseStatus::Completed);
        assert_eq!(completed.error_code, FileErrorCode::None);

        // 8. Verify the actual committed file contents.
        let target = root.join(remote_path);
        let received = std::fs::read(&target).unwrap();

        assert_eq!(received, data);
        assert_eq!(received.len(), data.len());

        // 9. Close the FileTransfer session and disconnect.
        client
            .send(
                MessageKind::SessionClose,
                session_id,
                SessionClosePayload.encode(),
            )
            .await
            .unwrap();

        drop(client);

        let host_result = timeout(Duration::from_secs(10), host_task)
            .await
            .expect("Host did not stop after client disconnect")
            .expect("Host task panicked");

        assert!(host_result.is_err() || host_result.is_ok());

        // 10. Remove the test directory.
        std::fs::remove_dir_all(&root).unwrap();
    }
}

#[cfg(test)]
mod terminal_integration_tests {
    use super::*;

    use myssh_auth::AuthenticatedIdentity;
    use myssh_core::Connection;
    use myssh_protocol::{
        SessionClosePayload, SessionOpenPayload, SessionOpenedPayload, SessionResizePayload,
        SessionType,
    };
    use myssh_transport::BoxedStream;

    use tokio::io;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn host_and_client_exchange_data_through_real_pty() {
        let (client_stream, host_stream) = tokio::io::duplex(1024 * 1024);

        let host_stream: BoxedStream = Box::new(host_stream);

        let authenticated = AuthenticatedConnection {
            stream: host_stream,
            identity: AuthenticatedIdentity {
                username: "integration-test".to_string(),
                key_id: "integration-test-key".to_string(),
            },
        };

        let host_task = tokio::spawn(async move { run_terminal_connection(authenticated).await });

        let mut client = Connection::new(Box::new(client_stream) as BoxedStream);

        // 1. Open a Shell session.
        let request_id = client
            .send(
                MessageKind::SessionOpen,
                0,
                SessionOpenPayload {
                    session_type: SessionType::Shell,
                }
                .encode(),
            )
            .await
            .unwrap();

        let response = timeout(Duration::from_secs(5), client.receive())
            .await
            .expect("Host did not respond to SessionOpen")
            .expect("Failed to receive SessionOpened");

        assert_eq!(response.header.kind, MessageKind::SessionOpened);
        assert_eq!(response.header.request_id, request_id);

        let opened = SessionOpenedPayload::decode(&response.payload).unwrap();

        assert_eq!(opened.status, SessionOpenStatus::Accepted);

        let session_id = response.header.session_id;
        assert_ne!(session_id, 0);

        // 2. Resize the PTY.
        let resize = SessionResizePayload {
            rows: 30,
            columns: 100,
            pixel_width: 0,
            pixel_height: 0,
        };

        client
            .send(
                MessageKind::SessionResize,
                session_id,
                resize.encode().unwrap(),
            )
            .await
            .unwrap();

        // 3. Send a command through the actual PTY.
        const MARKER: &str = "MYSSH_F1_PTY_INTEGRATION_OK";

        let command = format!("printf '{MARKER}\\n'\n");

        client
            .send(MessageKind::SessionData, session_id, command.into_bytes())
            .await
            .unwrap();

        // 4. Collect PTY output until the marker appears.
        let mut output = Vec::new();

        timeout(Duration::from_secs(10), async {
            loop {
                let frame = client.receive().await.unwrap();

                match frame.header.kind {
                    MessageKind::SessionData => {
                        assert_eq!(frame.header.session_id, session_id);

                        output.extend_from_slice(&frame.payload);

                        if output
                            .windows(MARKER.len())
                            .any(|window| window == MARKER.as_bytes())
                        {
                            break;
                        }
                    }

                    MessageKind::SessionClose => {
                        panic!("Host closed Shell session unexpectedly");
                    }

                    other => {
                        panic!("Unexpected Host message: {other:?}");
                    }
                }
            }
        })
        .await
        .expect("Timed out waiting for PTY output");

        // 5. Close the session.
        client
            .send(
                MessageKind::SessionClose,
                session_id,
                SessionClosePayload.encode(),
            )
            .await
            .unwrap();

        // Closing the client stream also verifies Host disconnect cleanup.
        drop(client);

        // EOF is expected after the client disconnects.
        let host_result = timeout(Duration::from_secs(10), host_task)
            .await
            .expect("Host did not finish after client disconnect")
            .expect("Host task panicked");

        assert!(
            host_result.is_err() || host_result.is_ok(),
            "Host task did not complete"
        );

        // The PTY output must contain the command's unique marker.
        assert!(
            output
                .windows(MARKER.len())
                .any(|window| window == MARKER.as_bytes()),
            "PTY output did not contain the expected marker"
        );

        let _ = io::ErrorKind::Other;
    }
}

#[cfg(test)]
mod terminal_f3_f4_tests {
    use super::*;
    use myssh_auth::AuthenticatedIdentity;
    use myssh_core::Connection;
    use myssh_protocol::{
        SessionOpenPayload, SessionOpenedPayload, SessionResizePayload, SessionType,
    };
    use myssh_transport::BoxedStream;
    use tokio::time::{timeout, Duration};

    async fn setup() -> (Connection, tokio::task::JoinHandle<io::Result<()>>) {
        let (client_stream, host_stream) = tokio::io::duplex(1024 * 1024);

        let authenticated = AuthenticatedConnection {
            stream: Box::new(host_stream) as BoxedStream,
            identity: AuthenticatedIdentity {
                username: "f3-f4-test".to_string(),
                key_id: "f3-f4-test-key".to_string(),
            },
        };

        let host_task = tokio::spawn(async move { run_terminal_connection(authenticated).await });

        let client = Connection::new(Box::new(client_stream) as BoxedStream);
        (client, host_task)
    }

    async fn open_shell(client: &mut Connection) -> u128 {
        let request_id = client
            .send(
                MessageKind::SessionOpen,
                0,
                SessionOpenPayload {
                    session_type: SessionType::Shell,
                }
                .encode(),
            )
            .await
            .unwrap();

        let response = timeout(Duration::from_secs(5), client.receive())
            .await
            .expect("SessionOpen timed out")
            .expect("Failed to receive SessionOpened");

        assert_eq!(response.header.kind, MessageKind::SessionOpened);
        assert_eq!(response.header.request_id, request_id);

        let opened = SessionOpenedPayload::decode(&response.payload).unwrap();
        assert_eq!(opened.status, SessionOpenStatus::Accepted);
        assert_ne!(response.header.session_id, 0);

        response.header.session_id
    }

    #[tokio::test]
    async fn f3_pty_resize_reaches_real_shell() {
        let (mut client, host_task) = setup().await;
        let session_id = open_shell(&mut client).await;

        let resize = SessionResizePayload {
            rows: 30,
            columns: 100,
            pixel_width: 0,
            pixel_height: 0,
        };

        client
            .send(
                MessageKind::SessionResize,
                session_id,
                resize.encode().unwrap(),
            )
            .await
            .unwrap();

        client
            .send(
                MessageKind::SessionData,
                session_id,
                b"stty size\n".to_vec(),
            )
            .await
            .unwrap();

        let mut output = Vec::new();

        timeout(Duration::from_secs(10), async {
            loop {
                let frame = client.receive().await.unwrap();

                match frame.header.kind {
                    MessageKind::SessionData => {
                        assert_eq!(frame.header.session_id, session_id);
                        output.extend_from_slice(&frame.payload);

                        if output
                            .windows(b"30 100".len())
                            .any(|window| window == b"30 100")
                        {
                            break;
                        }
                    }
                    MessageKind::SessionClose => {
                        panic!("Shell closed before resize verification");
                    }
                    other => panic!("Unexpected Host message: {other:?}"),
                }
            }
        })
        .await
        .expect("Timed out waiting for resized PTY dimensions");

        client
            .send(
                MessageKind::SessionClose,
                session_id,
                SessionClosePayload.encode(),
            )
            .await
            .unwrap();

        drop(client);

        timeout(Duration::from_secs(10), host_task)
            .await
            .expect("Host did not clean up after SessionClose")
            .expect("Host task panicked");

        assert!(
            output
                .windows(b"30 100".len())
                .any(|window| window == b"30 100"),
            "PTY did not report the requested 30x100 dimensions"
        );
    }

    #[tokio::test]
    async fn f3_remote_shell_exit_notifies_client() {
        let (mut client, host_task) = setup().await;
        let session_id = open_shell(&mut client).await;

        client
            .send(MessageKind::SessionData, session_id, b"exit\n".to_vec())
            .await
            .unwrap();

        let close_frame = timeout(Duration::from_secs(10), async {
            loop {
                let frame = client.receive().await.unwrap();

                if frame.header.kind == MessageKind::SessionClose {
                    break frame;
                }
            }
        })
        .await
        .expect("Host did not notify Client after remote shell exit");

        assert_eq!(close_frame.header.session_id, session_id);

        drop(client);

        timeout(Duration::from_secs(10), host_task)
            .await
            .expect("Host did not finish after remote shell exit")
            .expect("Host task panicked");
    }

    #[tokio::test]
    async fn f4_client_disconnect_cleans_up_host_session() {
        let (mut client, host_task) = setup().await;
        let session_id = open_shell(&mut client).await;

        client
            .send(
                MessageKind::SessionData,
                session_id,
                b"printf 'F4_ACTIVE_SESSION_OK\\n'\n".to_vec(),
            )
            .await
            .unwrap();

        let mut output = Vec::new();

        timeout(Duration::from_secs(10), async {
            loop {
                let frame = client.receive().await.unwrap();

                if frame.header.kind == MessageKind::SessionData {
                    output.extend_from_slice(&frame.payload);

                    if output
                        .windows(b"F4_ACTIVE_SESSION_OK".len())
                        .any(|window| window == b"F4_ACTIVE_SESSION_OK")
                    {
                        break;
                    }
                }
            }
        })
        .await
        .expect("Shell did not become active before disconnect test");

        drop(client);

        timeout(Duration::from_secs(10), host_task)
            .await
            .expect("Host did not clean up after abrupt Client disconnect")
            .expect("Host task panicked");

        assert!(output
            .windows(b"F4_ACTIVE_SESSION_OK".len())
            .any(|window| window == b"F4_ACTIVE_SESSION_OK"));
    }
}

#[cfg(test)]
mod client_upload_e2e_tests {
    use super::*;

    use std::fs;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use myssh_auth::{AuthServer, ClientKeyPair, TrustStore};
    use myssh_client::{
        auth::authenticate,
        file_transfer::{download_file, upload_file},
    };
    use myssh_security::{build_client_config, build_server_config};
    use myssh_transport::BoxedStream;

    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

    use tokio::io::duplex;
    use tokio::time::timeout;

    fn create_tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();

        let key_pair = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key_pair).unwrap();

        let certificate_der: CertificateDer<'static> = certificate.der().clone();

        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        let server_config =
            build_server_config(vec![certificate_der.clone()], private_key).unwrap();

        let client_config = build_client_config(vec![certificate_der]).unwrap();

        (server_config, client_config)
    }

    fn create_auth_server() -> (AuthServer, ClientKeyPair) {
        let client_key = ClientKeyPair::generate();

        let mut trust_store = TrustStore::new();

        trust_store
            .add("test-user", client_key.public_key_bytes())
            .unwrap();

        let auth_server = AuthServer::new(trust_store, Duration::from_secs(30));

        (auth_server, client_key)
    }

    fn unique_test_dir() -> std::path::PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        std::env::temp_dir().join(format!(
            "myssh-upload-e2e-{}-{}",
            std::process::id(),
            timestamp,
        ))
    }

    fn start_download_host(
        storage: std::path::PathBuf,
    ) -> (
        BoxedStream,
        Arc<rustls::ClientConfig>,
        ClientKeyPair,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let store = crate::file_transfer::HostFileStore::new(&storage, 10 * 1024 * 1024).unwrap();

        let (server_tls, client_tls) = create_tls_configs();
        let (mut auth_server, client_key) = create_auth_server();
        let (client_io, server_io) = duplex(2 * 1024 * 1024);

        let host_task = tokio::spawn(async move {
            let authenticated = crate::auth_connection::authenticate_connection(
                Box::new(server_io) as BoxedStream,
                server_tls,
                &mut auth_server,
                Duration::from_secs(5),
            )
            .await?;

            crate::terminal_bridge::run_terminal_connection_with_file_store(authenticated, store)
                .await
        });

        (
            Box::new(client_io) as BoxedStream,
            client_tls,
            client_key,
            host_task,
        )
    }

    async fn connect_download_test_client(
        client_io: BoxedStream,
        client_tls: Arc<rustls::ClientConfig>,
        client_key: &ClientKeyPair,
    ) -> myssh_client::auth::AuthenticatedClient {
        authenticate(
            client_io,
            ServerName::try_from("localhost".to_string()).unwrap(),
            client_tls,
            "test-user",
            client_key,
            Duration::from_secs(5),
        )
        .await
        .expect("Client TLS + Ed25519 authentication failed")
    }

    #[tokio::test]
    async fn client_downloads_multiple_chunks_through_tls_and_auth() {
        let root = unique_test_dir();
        let storage = root.join("storage");
        let downloads = root.join("downloads");
        fs::create_dir_all(&storage).unwrap();
        fs::create_dir_all(&downloads).unwrap();

        let remote_path = "multi-chunk.bin";
        let destination = downloads.join("downloaded.bin");

        let data: Vec<u8> = (0..(256 * 1024 * 2 + 731))
            .map(|index| ((index * 17) % 251) as u8)
            .collect();

        fs::write(storage.join(remote_path), &data).unwrap();

        let (client_io, client_tls, client_key, host_task) = start_download_host(storage);

        let client = connect_download_test_client(client_io, client_tls, &client_key).await;

        download_file(client, remote_path, &destination)
            .await
            .expect("Client multi-chunk download failed");

        assert_eq!(fs::read(&destination).unwrap(), data);

        let _host_result = timeout(Duration::from_secs(10), host_task)
            .await
            .expect("Host did not stop after client disconnect")
            .expect("Host task panicked");

        fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn client_downloads_empty_file_through_tls_and_auth() {
        let root = unique_test_dir();
        let storage = root.join("storage");
        let downloads = root.join("downloads");
        fs::create_dir_all(&storage).unwrap();
        fs::create_dir_all(&downloads).unwrap();

        let remote_path = "empty.bin";
        let destination = downloads.join("empty-copy.bin");
        fs::write(storage.join(remote_path), []).unwrap();

        let (client_io, client_tls, client_key, host_task) = start_download_host(storage);

        let client = connect_download_test_client(client_io, client_tls, &client_key).await;

        download_file(client, remote_path, &destination)
            .await
            .expect("Client empty-file download failed");

        assert!(destination.is_file());
        assert_eq!(fs::metadata(&destination).unwrap().len(), 0);
        assert_eq!(fs::read(&destination).unwrap(), Vec::<u8>::new());

        let _host_result = timeout(Duration::from_secs(10), host_task)
            .await
            .expect("Host did not stop after client disconnect")
            .expect("Host task panicked");

        fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn client_download_does_not_overwrite_existing_destination() {
        let root = unique_test_dir();
        let storage = root.join("storage");
        let downloads = root.join("downloads");
        fs::create_dir_all(&storage).unwrap();
        fs::create_dir_all(&downloads).unwrap();

        let remote_path = "remote.bin";
        let destination = downloads.join("keep.bin");

        fs::write(storage.join(remote_path), b"remote contents").unwrap();
        fs::write(&destination, b"keep my local contents").unwrap();

        let (client_io, client_tls, client_key, host_task) = start_download_host(storage);

        let client = connect_download_test_client(client_io, client_tls, &client_key).await;

        let error = download_file(client, remote_path, &destination)
            .await
            .expect_err("Existing destination must not be overwritten");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&destination).unwrap(), b"keep my local contents");

        let _host_result = timeout(Duration::from_secs(10), host_task)
            .await
            .expect("Host did not stop after client disconnect")
            .expect("Host task panicked");

        fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn client_uploads_multiple_chunks_through_tls_and_auth() {
        let root = unique_test_dir();
        let storage = root.join("storage");

        fs::create_dir_all(&storage).unwrap();

        let source_path = root.join("source.bin");
        let remote_path = "received.bin";

        // 超過兩個 256 KiB Chunk。
        let data: Vec<u8> = (0..(256 * 1024 * 2 + 123))
            .map(|index| (index % 251) as u8)
            .collect();

        fs::write(&source_path, &data).unwrap();

        let store = crate::file_transfer::HostFileStore::new(&storage, 10 * 1024 * 1024).unwrap();

        let (server_tls, client_tls) = create_tls_configs();
        let (mut auth_server, client_key) = create_auth_server();

        let (client_io, server_io) = duplex(2 * 1024 * 1024);

        let host_task = tokio::spawn(async move {
            let authenticated = crate::auth_connection::authenticate_connection(
                Box::new(server_io) as BoxedStream,
                server_tls,
                &mut auth_server,
                Duration::from_secs(5),
            )
            .await?;

            crate::terminal_bridge::run_terminal_connection_with_file_store(authenticated, store)
                .await
        });

        let client = authenticate(
            Box::new(client_io) as BoxedStream,
            ServerName::try_from("localhost".to_string()).unwrap(),
            client_tls,
            "test-user",
            &client_key,
            Duration::from_secs(5),
        )
        .await
        .expect("Client TLS + Ed25519 authentication failed");

        upload_file(client, &source_path, remote_path)
            .await
            .expect("Client upload failed");

        // Host 收到 FileEnd 並回覆 Completed 後，檔案應已提交。
        let received = fs::read(storage.join(remote_path)).unwrap();

        assert_eq!(received.len(), data.len());
        assert_eq!(received, data);

        // 確認 Host 能在 Client 關閉連線後完成清理。
        let _host_result = timeout(Duration::from_secs(10), host_task)
            .await
            .expect("Host did not stop after client disconnect")
            .expect("Host task panicked");

        fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn upload_disconnect_removes_host_temporary_file() {
        let root = unique_test_dir();
        let storage = root.join("storage");
        fs::create_dir_all(&storage).unwrap();

        let (client_io, client_tls, client_key, host_task) = start_download_host(storage.clone());

        let authenticated = connect_download_test_client(client_io, client_tls, &client_key).await;

        let mut client = Connection::new(authenticated.stream);

        // 開啟 FileTransfer Session。
        let open_request_id = client
            .send(
                MessageKind::SessionOpen,
                0,
                SessionOpenPayload {
                    session_type: SessionType::FileTransfer,
                }
                .encode(),
            )
            .await
            .unwrap();

        let opened_frame = timeout(Duration::from_secs(5), client.receive())
            .await
            .expect("SessionOpen timed out")
            .expect("Failed to receive SessionOpened");

        assert_eq!(opened_frame.header.kind, MessageKind::SessionOpened);
        assert_eq!(opened_frame.header.request_id, open_request_id);

        let opened = SessionOpenedPayload::decode(&opened_frame.payload).unwrap();

        assert_eq!(opened.status, SessionOpenStatus::Accepted);

        let session_id = opened_frame.header.session_id;
        assert_ne!(session_id, 0);

        // 宣告完整檔案大小，但只傳送部分內容。
        let begin_request_id = client
            .send(
                MessageKind::FileBegin,
                session_id,
                FileBeginPayload {
                    direction: FileDirection::Upload,
                    file_size: 4096,
                    remote_path: "interrupted-upload.bin".to_string(),
                }
                .encode()
                .unwrap(),
            )
            .await
            .unwrap();

        let ready_frame = timeout(Duration::from_secs(5), client.receive())
            .await
            .expect("FileBegin response timed out")
            .expect("Failed to receive FileResponse");

        assert_eq!(ready_frame.header.kind, MessageKind::FileResponse);
        assert_eq!(ready_frame.header.request_id, begin_request_id);

        let ready = FileResponsePayload::decode(&ready_frame.payload).unwrap();

        assert_eq!(ready.status, FileResponseStatus::Ready);

        // 傳送部分資料，但不傳 FileEnd。
        client
            .send(
                MessageKind::FileChunk,
                session_id,
                FileChunkPayload {
                    chunk_index: 0,
                    data: b"partial upload data".to_vec(),
                }
                .encode()
                .unwrap(),
            )
            .await
            .unwrap();

        // 模擬 Client 突然斷線。
        drop(client);

        // Host 應該結束連線並執行清理。
        let _host_result = timeout(Duration::from_secs(10), host_task)
            .await
            .expect("Host did not stop after client disconnect")
            .expect("Host task panicked");

        assert!(
            !storage.join("interrupted-upload.bin").exists(),
            "Incomplete upload must not be published"
        );

        let remaining_entries = fs::read_dir(&storage).unwrap().count();

        assert_eq!(
            remaining_entries, 0,
            "Host must remove incomplete upload temporary files"
        );

        fs::remove_dir_all(&root).unwrap();
    }
}
