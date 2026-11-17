use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use myssh_core::{Connection, ConnectionWriter};
use myssh_protocol::{
    FileBeginPayload, FileChunkPayload, FileDirection, FileEndPayload, FileErrorCode,
    FileRequestPayload, FileResponsePayload, FileResponseStatus, Frame, MessageKind,
    SessionClosePayload, SessionOpenPayload, SessionOpenStatus, SessionOpenedPayload, SessionType,
    FILE_CHUNK_SIZE,
};
use sha2::{Digest, Sha256};

use crate::auth::AuthenticatedClient;

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn response_error(response: FileResponsePayload) -> io::Error {
    let kind = match response.error_code {
        FileErrorCode::None | FileErrorCode::Io => io::ErrorKind::Other,
        FileErrorCode::InvalidRequest => io::ErrorKind::InvalidInput,
        FileErrorCode::NotFound => io::ErrorKind::NotFound,
        FileErrorCode::PermissionDenied => io::ErrorKind::PermissionDenied,
        FileErrorCode::AlreadyExists => io::ErrorKind::AlreadyExists,
        FileErrorCode::IntegrityMismatch | FileErrorCode::Protocol => io::ErrorKind::InvalidData,
    };

    io::Error::new(
        kind,
        format!(
            "Host file transfer error: {:?} ({:?})",
            response.status, response.error_code
        ),
    )
}

fn validate_file_response(
    frame: &Frame,
    session_id: u128,
    request_id: u64,
) -> io::Result<FileResponsePayload> {
    if frame.header.kind != MessageKind::FileResponse {
        return Err(invalid_data("Expected FileResponse"));
    }

    if frame.header.session_id != session_id {
        return Err(invalid_data("FileResponse session ID mismatch"));
    }

    if frame.header.request_id != request_id {
        return Err(invalid_data("FileResponse request ID mismatch"));
    }

    FileResponsePayload::decode(&frame.payload)
}

async fn close_session_best_effort(writer: &mut ConnectionWriter, session_id: u128) {
    let _ = writer
        .send(
            MessageKind::SessionClose,
            session_id,
            SessionClosePayload.encode(),
        )
        .await;
}

/// Atomically publish a completed download without replacing an existing file.
/// Supported on Linux and Android.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn publish_noclobber(temp: &Path, target: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let temp = CString::new(temp.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid temporary path"))?;

    let target = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid target path"))?;

    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            temp.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };

    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn publish_noclobber(_temp: &Path, _target: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Atomic no-clobber publication is not supported on this platform",
    ))
}

const MAX_DOWNLOAD_SIZE: u64 = 2 * 1024 * 1024 * 1024;
static DOWNLOAD_TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// A same-directory temporary file that is published only after validation.
struct DownloadTemp {
    file: File,
    temp_path: PathBuf,
    destination: PathBuf,
    committed: bool,
}

impl DownloadTemp {
    fn create(destination: &Path) -> io::Result<Self> {
        let file_name = destination.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Download destination must include a file name",
            )
        })?;

        if file_name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Download destination file name is empty",
            ));
        }

        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        let parent_metadata = fs::metadata(parent)?;

        if !parent_metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "Download destination parent is not a directory",
            ));
        }

        match fs::symlink_metadata(destination) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Download destination already exists",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let name = file_name.to_string_lossy();

        for _ in 0..128 {
            let counter = DOWNLOAD_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let temp_name = format!(".{name}.myssh-{}-{counter}.part", std::process::id());
            let temp_path = parent.join(temp_name);

            match OpenOptions::new()
                .write(true)
                .read(true)
                .create_new(true)
                .open(&temp_path)
            {
                Ok(file) => {
                    return Ok(Self {
                        file,
                        temp_path,
                        destination: destination.to_path_buf(),
                        committed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Could not allocate a unique download temporary file",
        ))
    }

    fn commit(mut self) -> io::Result<()> {
        self.file.sync_all()?;

        // Atomically move the completed temporary file into place.
        // RENAME_NOREPLACE guarantees that an existing destination is preserved.
        publish_noclobber(&self.temp_path, &self.destination)?;

        self.committed = true;

        // Best-effort directory sync after publication.
        if let Some(parent) = self.destination.parent() {
            if let Ok(directory) = File::open(parent) {
                let _ = directory.sync_all();
            }
        }

        Ok(())
    }
}

impl Drop for DownloadTemp {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

/// Upload one local regular file to the Host's configured file-transfer root.
///
/// The connection must already have completed TLS and Ed25519 authentication.
/// The remote path is relative to the Host's configured storage root.
pub async fn upload_file(
    client: AuthenticatedClient,
    local_path: impl AsRef<Path>,
    remote_path: &str,
) -> io::Result<()> {
    let mut file = File::open(local_path)?;
    let metadata = file.metadata()?;

    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Upload source must be a regular file",
        ));
    }

    let expected_size = metadata.len();

    let begin_payload = FileBeginPayload {
        direction: FileDirection::Upload,
        file_size: expected_size,
        remote_path: remote_path.to_string(),
    }
    .encode()?;

    let mut connection = Connection::new(client.stream);

    // Open FileTransfer session.
    let open_request_id = connection
        .send(
            MessageKind::SessionOpen,
            0,
            SessionOpenPayload {
                session_type: SessionType::FileTransfer,
            }
            .encode(),
        )
        .await?;

    let opened_frame = connection.receive().await?;

    if opened_frame.header.kind != MessageKind::SessionOpened {
        return Err(invalid_data("Expected SessionOpened"));
    }

    if opened_frame.header.request_id != open_request_id {
        return Err(invalid_data("SessionOpened request ID mismatch"));
    }

    let opened = SessionOpenedPayload::decode(&opened_frame.payload)?;

    if opened.status != SessionOpenStatus::Accepted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("FileTransfer session rejected: {:?}", opened.status),
        ));
    }

    let session_id = opened_frame.header.session_id;

    if session_id == 0 {
        return Err(invalid_data("Host returned session ID zero"));
    }

    let (mut reader, mut writer) = connection.into_split();

    // Always attempt to close the session after transfer processing.
    let transfer_result: io::Result<()> = async {
        // Tell Host the file metadata and wait for Ready.
        let begin_request_id = writer
            .send(MessageKind::FileBegin, session_id, begin_payload)
            .await?;

        let ready_frame = reader.receive().await?;
        let ready = validate_file_response(&ready_frame, session_id, begin_request_id)?;

        if ready.status != FileResponseStatus::Ready {
            return Err(response_error(ready));
        }

        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; FILE_CHUNK_SIZE];

        let mut remaining = expected_size;
        let mut total_chunks = 0u64;
        let mut total_size = 0u64;

        // Stream the file in chunks no larger than FILE_CHUNK_SIZE.
        while remaining > 0 {
            let wanted = remaining.min(FILE_CHUNK_SIZE as u64) as usize;
            let mut filled = 0usize;

            while filled < wanted {
                let count = file.read(&mut buffer[filled..wanted])?;

                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Local file became shorter during upload",
                    ));
                }

                filled += count;
            }

            let chunk_data = buffer[..wanted].to_vec();
            hasher.update(&chunk_data);

            let payload = FileChunkPayload {
                chunk_index: total_chunks,
                data: chunk_data,
            }
            .encode()?;

            writer
                .send(MessageKind::FileChunk, session_id, payload)
                .await?;

            total_chunks = total_chunks
                .checked_add(1)
                .ok_or_else(|| invalid_data("File chunk counter overflow"))?;

            total_size = total_size
                .checked_add(wanted as u64)
                .ok_or_else(|| invalid_data("File size counter overflow"))?;

            remaining -= wanted as u64;
        }

        // Detect file growth after the initial metadata check.
        let mut extra = [0u8; 1];

        if file.read(&mut extra)? != 0 {
            return Err(invalid_data("Local file grew during upload"));
        }

        if total_size != expected_size {
            return Err(invalid_data("Uploaded size does not match file metadata"));
        }

        let digest = hasher.finalize();
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&digest);

        let end_payload = FileEndPayload {
            total_chunks,
            total_size,
            sha256,
        }
        .encode();

        let end_request_id = writer
            .send(MessageKind::FileEnd, session_id, end_payload)
            .await?;

        let completed_frame = reader.receive().await?;

        let completed = validate_file_response(&completed_frame, session_id, end_request_id)?;

        if completed.status != FileResponseStatus::Completed {
            return Err(response_error(completed));
        }

        Ok(())
    }
    .await;

    close_session_best_effort(&mut writer, session_id).await;

    transfer_result
}

/// Download one regular file from the Host's configured file-transfer root.
///
/// The connection must already have completed TLS and Ed25519 authentication.
/// The local destination is never overwritten. The file is published only
/// after the Host's final Completed response and SHA-256 verification.
pub async fn download_file(
    client: AuthenticatedClient,
    remote_path: &str,
    local_path: impl AsRef<Path>,
) -> io::Result<()> {
    let request_payload = FileRequestPayload {
        remote_path: remote_path.to_owned(),
    }
    .encode()?;

    let mut connection = Connection::new(client.stream);

    // Open a dedicated FileTransfer session.
    let open_request_id = connection
        .send(
            MessageKind::SessionOpen,
            0,
            SessionOpenPayload {
                session_type: SessionType::FileTransfer,
            }
            .encode(),
        )
        .await?;

    let opened_frame = connection.receive().await?;

    if opened_frame.header.kind != MessageKind::SessionOpened {
        return Err(invalid_data("Expected SessionOpened"));
    }

    if opened_frame.header.request_id != open_request_id {
        return Err(invalid_data("SessionOpened request ID mismatch"));
    }

    let opened = SessionOpenedPayload::decode(&opened_frame.payload)?;

    if opened.status != SessionOpenStatus::Accepted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("FileTransfer session rejected: {:?}", opened.status),
        ));
    }

    let session_id = opened_frame.header.session_id;

    if session_id == 0 {
        return Err(invalid_data("Host returned session ID zero"));
    }

    let (mut reader, mut writer) = connection.into_split();

    let transfer_result: io::Result<()> = async {
        // Ask Host to start the download.
        let request_id = writer
            .send(MessageKind::FileRequest, session_id, request_payload)
            .await?;

        // Host first acknowledges that the request was accepted.
        let ready_frame = reader.receive().await?;
        let ready = validate_file_response(&ready_frame, session_id, request_id)?;

        if ready.status != FileResponseStatus::Ready {
            return Err(response_error(ready));
        }

        // Host then sends the file metadata.
        let begin_frame = reader.receive().await?;

        if begin_frame.header.kind != MessageKind::FileBegin {
            return Err(invalid_data("Expected FileBegin"));
        }

        if begin_frame.header.session_id != session_id {
            return Err(invalid_data("FileBegin session ID mismatch"));
        }

        if begin_frame.header.request_id != request_id {
            return Err(invalid_data("FileBegin request ID mismatch"));
        }

        let begin = FileBeginPayload::decode(&begin_frame.payload)?;

        if begin.direction != FileDirection::Download {
            return Err(invalid_data("Host returned a non-download FileBegin"));
        }

        if begin.remote_path != remote_path {
            return Err(invalid_data("Host returned a different remote path"));
        }

        if begin.file_size > MAX_DOWNLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Remote file exceeds the 2 GiB client download limit",
            ));
        }

        // Do not create a local temporary file until metadata is validated.
        let mut temp = DownloadTemp::create(local_path.as_ref()).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("Creating local download temporary file failed: {error}"),
            )
        })?;

        let mut hasher = Sha256::new();
        let mut expected_chunk_index = 0u64;
        let mut total_size = 0u64;

        // Receive chunks until FileEnd. A Failed response may arrive instead
        // if the Host encounters an error while streaming.
        let end_frame = loop {
            let frame = reader.receive().await?;

            if frame.header.session_id != session_id {
                return Err(invalid_data("Download frame session ID mismatch"));
            }

            match frame.header.kind {
                MessageKind::FileChunk => {
                    if frame.header.request_id != request_id {
                        return Err(invalid_data("FileChunk request ID mismatch"));
                    }

                    let chunk = FileChunkPayload::decode(&frame.payload)?;

                    if chunk.chunk_index != expected_chunk_index {
                        return Err(invalid_data("Download chunk index mismatch"));
                    }

                    let chunk_size = u64::try_from(chunk.data.len())
                        .map_err(|_| invalid_data("Download chunk size overflow"))?;

                    let new_total = total_size
                        .checked_add(chunk_size)
                        .ok_or_else(|| invalid_data("Download size overflow"))?;

                    if new_total > begin.file_size {
                        return Err(invalid_data("Host sent more data than declared"));
                    }

                    temp.file.write_all(&chunk.data).map_err(|error| {
                        io::Error::new(
                            error.kind(),
                            format!("Writing downloaded chunk failed: {error}"),
                        )
                    })?;
                    hasher.update(&chunk.data);

                    total_size = new_total;
                    expected_chunk_index = expected_chunk_index
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("Download chunk counter overflow"))?;
                }

                MessageKind::FileEnd => {
                    if frame.header.request_id != request_id {
                        return Err(invalid_data("FileEnd request ID mismatch"));
                    }

                    break frame;
                }

                MessageKind::FileResponse => {
                    let response = validate_file_response(&frame, session_id, request_id)?;

                    if response.status == FileResponseStatus::Failed
                        || response.status == FileResponseStatus::Rejected
                    {
                        return Err(response_error(response));
                    }

                    return Err(invalid_data(
                        "Unexpected FileResponse during download streaming",
                    ));
                }

                _ => {
                    return Err(invalid_data(
                        "Unexpected message kind during download streaming",
                    ));
                }
            }
        };

        let end = FileEndPayload::decode(&end_frame.payload)?;

        if end.total_chunks != expected_chunk_index {
            return Err(invalid_data("Download total chunk count mismatch"));
        }

        if end.total_size != total_size || total_size != begin.file_size {
            return Err(invalid_data("Download total file size mismatch"));
        }

        let digest = hasher.finalize();

        if digest.as_slice() != end.sha256 {
            return Err(invalid_data("Download SHA-256 mismatch"));
        }

        // Wait for the Host's final operation result before publishing locally.
        let completed_frame = reader.receive().await?;
        let completed = validate_file_response(&completed_frame, session_id, request_id)?;

        if completed.status != FileResponseStatus::Completed {
            return Err(response_error(completed));
        }

        temp.commit().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("Committing downloaded file failed: {error}"),
            )
        })?;
        Ok(())
    }
    .await;

    close_session_best_effort(&mut writer, session_id).await;

    transfer_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_host_file_errors_to_io_kinds() {
        let cases = [
            (FileErrorCode::InvalidRequest, io::ErrorKind::InvalidInput),
            (FileErrorCode::NotFound, io::ErrorKind::NotFound),
            (
                FileErrorCode::PermissionDenied,
                io::ErrorKind::PermissionDenied,
            ),
            (FileErrorCode::AlreadyExists, io::ErrorKind::AlreadyExists),
            (FileErrorCode::IntegrityMismatch, io::ErrorKind::InvalidData),
            (FileErrorCode::Protocol, io::ErrorKind::InvalidData),
        ];

        for (code, expected) in cases {
            let error = response_error(FileResponsePayload {
                status: FileResponseStatus::Rejected,
                error_code: code,
            });

            assert_eq!(error.kind(), expected);
        }
    }

    #[test]
    fn interrupted_download_removes_temporary_file() {
        fn simulate_interrupted_download(
            destination: &Path,
            temp_path_out: &mut Option<PathBuf>,
        ) -> io::Result<()> {
            let mut temp = DownloadTemp::create(destination)?;

            *temp_path_out = Some(temp.temp_path.clone());

            temp.file.write_all(b"partial download data")?;

            // 模擬下載期間連線中斷。
            // 函式返回錯誤時，temp 會離開作用域並觸發 Drop。
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "simulated download disconnect",
            ))
        }

        let counter = DOWNLOAD_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);

        let root = std::env::temp_dir().join(format!(
            "myssh-download-disconnect-{}-{}",
            std::process::id(),
            counter
        ));

        fs::create_dir_all(&root).unwrap();

        let destination = root.join("incomplete.bin");
        let mut temp_path = None;

        let error = simulate_interrupted_download(&destination, &mut temp_path)
            .expect_err("Simulated disconnect should fail");

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);

        let temp_path = temp_path.expect("Temporary file path was not captured");

        assert!(
            !temp_path.exists(),
            "Temporary download file must be removed after interruption"
        );

        assert!(
            !destination.exists(),
            "Incomplete destination file must not be published"
        );

        fs::remove_dir_all(&root).unwrap();
    }
}
