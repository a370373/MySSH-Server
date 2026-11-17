use portable_pty::{native_pty_system, Child, CommandBuilder, ExitStatus, MasterPty, PtySize};
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::path::PathBuf;

/// Creates native pseudo-terminal sessions for authenticated MySSH clients.
///
/// The shell runs with the operating-system identity of the Host process.
/// MySSH authentication does not automatically change the OS user.
pub struct PtyManager;

impl PtyManager {
    pub fn new() -> Self {
        Self
    }

    /// Spawn the default interactive shell for this Host process.
    pub fn spawn_default_shell(&self, size: PtySize) -> io::Result<PtySession> {
        validate_size(size)?;

        let shell = default_shell_path()?;
        self.spawn_shell_program(shell.as_os_str(), size)
    }

    fn spawn_shell_program(&self, shell: &OsStr, size: PtySize) -> io::Result<PtySession> {
        let system = native_pty_system();

        let pair = system.openpty(size).map_err(to_io_error)?;

        let mut command = CommandBuilder::new(shell);

        command.env("TERM", "xterm-256color");

        #[cfg(unix)]
        command.arg("-i");

        let mut child = pair.slave.spawn_command(command).map_err(to_io_error)?;

        let reader = match pair.master.try_clone_reader() {
            Ok(reader) => reader,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(to_io_error(error));
            }
        };

        let writer = match pair.master.take_writer() {
            Ok(writer) => writer,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(to_io_error(error));
            }
        };

        Ok(PtySession {
            master: pair.master,
            reader: Some(reader),
            writer: Some(writer),
            child,
            closed: false,
        })
    }
}

/// One running PTY session.
///
/// Reader and Writer are blocking std::io interfaces.
/// Network integration must move blocking operations to dedicated
/// blocking threads or an appropriate blocking executor.
pub struct PtySession {
    master: Box<dyn MasterPty + Send>,
    reader: Option<Box<dyn Read + Send>>,
    writer: Option<Box<dyn Write + Send>>,
    child: Box<dyn Child + Send + Sync>,
    closed: bool,
}

impl PtySession {
    /// Read bytes produced by the remote shell.
    pub fn read_output(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let reader = self
            .reader
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "PTY output is closed"))?;

        reader.read(buffer)
    }

    /// Move the blocking PTY reader to a dedicated I/O worker.
    pub fn take_reader(&mut self) -> io::Result<Box<dyn Read + Send>> {
        self.reader.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "PTY reader was already taken")
        })
    }

    /// Move the blocking PTY writer to a dedicated I/O worker.
    pub fn take_writer(&mut self) -> io::Result<Box<dyn Write + Send>> {
        self.writer.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "PTY writer was already taken")
        })
    }

    /// Send raw input bytes to the remote shell.
    pub fn write_input(&mut self, data: &[u8]) -> io::Result<()> {
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "PTY input is closed"))?;

        writer.write_all(data)?;
        writer.flush()
    }

    /// Change the terminal dimensions.
    pub fn resize(&self, size: PtySize) -> io::Result<()> {
        validate_size(size)?;
        self.master.resize(size).map_err(to_io_error)
    }

    /// Return the current terminal dimensions.
    pub fn size(&self) -> io::Result<PtySize> {
        self.master.get_size().map_err(to_io_error)
    }

    /// Check whether the shell process has exited.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Return the child process ID, when available.
    pub fn process_id(&self) -> Option<u32> {
        self.child.process_id()
    }

    /// Close input, terminate a still-running shell, and reap the child.
    pub fn close(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.closed {
            return Ok(None);
        }

        // Close any I/O handles still owned by this session.
        self.reader.take();
        self.writer.take();

        if self.child.try_wait()?.is_none() {
            self.child.kill().map_err(to_io_error)?;
        }

        let status = self.child.wait().map_err(to_io_error)?;
        self.closed = true;

        Ok(Some(status))
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        if self.closed {
            return;
        }

        self.reader.take();
        self.writer.take();

        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }

        let _ = self.child.wait();
        self.closed = true;
    }
}

fn validate_size(size: PtySize) -> io::Result<()> {
    if size.rows == 0 || size.cols == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PTY rows and columns must be non-zero",
        ));
    }

    Ok(())
}

fn to_io_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

fn default_shell_path() -> io::Result<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(path) = std::env::var_os("COMSPEC") {
            let path = PathBuf::from(path);
            if path.is_file() {
                return Ok(path);
            }
        }

        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No usable default Windows shell was found",
        ));
    }

    #[cfg(unix)]
    {
        if let Some(path) = std::env::var_os("SHELL") {
            let path = PathBuf::from(path);

            if path.is_file() {
                return Ok(path);
            }
        }

        for candidate in ["/system/bin/sh", "/bin/sh"] {
            let path = PathBuf::from(candidate);

            if path.is_file() {
                return Ok(path);
            }
        }

        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No usable default Unix shell was found",
        ));
    }

    #[cfg(not(any(unix, windows)))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "PTY shell discovery is unsupported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_size() -> PtySize {
        PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        }
    }

    #[test]
    fn rejects_zero_terminal_dimensions() {
        let manager = PtyManager::new();

        let size = PtySize {
            rows: 0,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        };

        assert!(manager.spawn_default_shell(size).is_err());
    }

    #[test]
    fn opens_shell_and_reports_terminal_size() {
        let manager = PtyManager::new();
        let session = manager.spawn_default_shell(test_size()).unwrap();

        let actual = session.size().unwrap();

        assert_eq!(actual.rows, 24);
        assert_eq!(actual.cols, 80);
    }

    #[test]
    fn resizes_terminal() {
        let manager = PtyManager::new();
        let session = manager.spawn_default_shell(test_size()).unwrap();

        let new_size = PtySize {
            rows: 40,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        };

        session.resize(new_size).unwrap();

        let actual = session.size().unwrap();

        assert_eq!(actual.rows, 40);
        assert_eq!(actual.cols, 120);
    }

    #[test]
    fn exposes_child_process_id() {
        let manager = PtyManager::new();
        let session = manager.spawn_default_shell(test_size()).unwrap();

        assert!(session.process_id().is_some());
    }

    #[test]
    fn close_reaps_shell_process() {
        let manager = PtyManager::new();
        let mut session = manager.spawn_default_shell(test_size()).unwrap();

        let status = session.close().unwrap();

        assert!(status.is_some());
        assert!(session.is_closed());
    }
}
