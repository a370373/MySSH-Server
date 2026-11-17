use std::io::{self, Read, Write};
use std::thread::{self, JoinHandle};

use tokio::sync::mpsc;

use super::PtySession;

const IO_QUEUE_CAPACITY: usize = 16;
const IO_CHUNK_SIZE: usize = 16 * 1024;

/// Events produced by the blocking PTY workers.
pub enum PtyIoEvent {
    Output(Vec<u8>),
    ReaderClosed,
    ReaderError(io::Error),
    WriterError(io::Error),
}

/// Bridges blocking PTY I/O and asynchronous network tasks.
///
/// The caller must invoke shutdown() while the associated PtySession
/// is still available, so that the child process is stopped before
/// joining the blocking workers.
pub struct PtyIoBridge {
    input_tx: Option<mpsc::Sender<Vec<u8>>>,
    events_rx: Option<mpsc::Receiver<PtyIoEvent>>,
    reader_thread: Option<JoinHandle<()>>,
    writer_thread: Option<JoinHandle<()>>,
}

impl PtyIoBridge {
    /// Move the PTY reader and writer into dedicated blocking threads.
    pub fn new(pty: &mut PtySession) -> io::Result<Self> {
        let reader = pty.take_reader()?;
        let writer = pty.take_writer()?;

        let (events_tx, mut events_rx) = mpsc::channel(IO_QUEUE_CAPACITY);

        let (input_tx, input_rx) = mpsc::channel(IO_QUEUE_CAPACITY);

        let reader_events = events_tx.clone();

        let reader_thread = thread::Builder::new()
            .name("myssh-pty-reader".into())
            .spawn(move || {
                reader_worker(reader, reader_events);
            })?;

        let writer_thread = match thread::Builder::new()
            .name("myssh-pty-writer".into())
            .spawn(move || {
                writer_worker(writer, input_rx, events_tx);
            }) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = pty.close();
                events_rx.close();
                let _ = reader_thread.join();
                return Err(error);
            }
        };

        Ok(Self {
            input_tx: Some(input_tx),
            events_rx: Some(events_rx),
            reader_thread: Some(reader_thread),
            writer_thread: Some(writer_thread),
        })
    }

    /// Queue input bytes for the blocking PTY writer.
    pub async fn send_input(&self, data: Vec<u8>) -> io::Result<()> {
        let sender = self.input_tx.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "PTY input channel is closed")
        })?;

        sender
            .send(data)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "PTY writer worker has stopped"))
    }

    /// Receive output or worker status events.
    pub async fn recv_event(&mut self) -> Option<PtyIoEvent> {
        match self.events_rx.as_mut() {
            Some(receiver) => receiver.recv().await,
            None => None,
        }
    }

    /// Transfer ownership of the event receiver to a forwarding task.
    pub fn take_event_receiver(&mut self) -> io::Result<mpsc::Receiver<PtyIoEvent>> {
        self.events_rx.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "PTY event receiver has already been taken",
            )
        })
    }

    /// Stop both workers and close the associated PTY process.
    pub fn shutdown(
        &mut self,
        pty: &mut PtySession,
    ) -> io::Result<Option<portable_pty::ExitStatus>> {
        // Stop accepting new input and let the writer channel close.
        self.input_tx.take();

        // Terminate and reap the shell so a blocked PTY reader can exit.
        let close_result = pty.close();

        // Wake workers waiting to publish events.
        if let Some(receiver) = self.events_rx.as_mut() {
            receiver.close();
        }

        let reader_result = join_worker(&mut self.reader_thread);
        let writer_result = join_worker(&mut self.writer_thread);

        let status = close_result?;
        reader_result?;
        writer_result?;

        Ok(status)
    }
}

fn reader_worker(mut reader: Box<dyn Read + Send>, events: mpsc::Sender<PtyIoEvent>) {
    let mut buffer = vec![0u8; IO_CHUNK_SIZE];

    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                let _ = events.blocking_send(PtyIoEvent::ReaderClosed);
                break;
            }
            Ok(count) => {
                let output = buffer[..count].to_vec();

                if events.blocking_send(PtyIoEvent::Output(output)).is_err() {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                continue;
            }
            Err(error) => {
                let _ = events.blocking_send(PtyIoEvent::ReaderError(error));
                break;
            }
        }
    }
}

fn writer_worker(
    mut writer: Box<dyn Write + Send>,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    events: mpsc::Sender<PtyIoEvent>,
) {
    while let Some(data) = input_rx.blocking_recv() {
        if let Err(error) = writer.write_all(&data).and_then(|_| writer.flush()) {
            let _ = events.blocking_send(PtyIoEvent::WriterError(error));
            break;
        }
    }
}

fn join_worker(handle: &mut Option<JoinHandle<()>>) -> io::Result<()> {
    let Some(handle) = handle.take() else {
        return Ok(());
    };

    handle
        .join()
        .map_err(|_| io::Error::other("PTY I/O worker thread panicked"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::PtyManager;
    use portable_pty::PtySize;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn bridge_forwards_shell_output() {
        let manager = PtyManager::new();

        let mut pty = manager
            .spawn_default_shell(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();

        let mut bridge = PtyIoBridge::new(&mut pty).unwrap();
        let marker = "MYSSH_BRIDGE_TEST_MARKER";

        bridge
            .send_input(format!("printf '{}\\n'\n", marker).into_bytes())
            .await
            .unwrap();

        let found = timeout(Duration::from_secs(5), async {
            let mut output = Vec::new();

            loop {
                match bridge.recv_event().await {
                    Some(PtyIoEvent::Output(data)) => {
                        output.extend_from_slice(&data);

                        if String::from_utf8_lossy(&output).contains(marker) {
                            return true;
                        }
                    }
                    Some(PtyIoEvent::ReaderError(_)) | None => {
                        return false;
                    }
                    Some(PtyIoEvent::ReaderClosed) => {
                        return false;
                    }
                    Some(PtyIoEvent::WriterError(_)) => {
                        return false;
                    }
                }
            }
        })
        .await
        .unwrap_or(false);

        let shutdown_result = bridge.shutdown(&mut pty);

        assert!(found, "Shell output did not reach the async bridge");
        shutdown_result.unwrap();
    }
}
