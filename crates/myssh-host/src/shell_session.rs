use std::collections::HashMap;
use std::io;

use myssh_core::{Session, SessionKind, SessionManager};
use myssh_protocol::{
    Frame, MessageKind, SessionOpenPayload, SessionOpenStatus, SessionOpenedPayload,
    SessionResizePayload, SessionType,
};
use portable_pty::{ExitStatus, PtySize};
use tokio::sync::mpsc;

use crate::pty::{PtyIoBridge, PtyIoEvent, PtyManager, PtySession};

const DEFAULT_PTY_SIZE: PtySize = PtySize {
    rows: 24,
    cols: 80,
    pixel_width: 0,
    pixel_height: 0,
};

/// A Shell session combines a Core session with its native PTY.
pub struct ShellSession {
    pub session: Session,
    pty: PtySession,
    bridge: PtyIoBridge,
}

impl ShellSession {
    pub fn pty(&self) -> &PtySession {
        &self.pty
    }

    pub fn pty_mut(&mut self) -> &mut PtySession {
        &mut self.pty
    }

    /// Resize the native terminal using a decoded protocol payload.
    pub fn resize(&self, size: SessionResizePayload) -> io::Result<()> {
        self.pty.resize(PtySize {
            rows: size.rows,
            cols: size.columns,
            pixel_width: size.pixel_width,
            pixel_height: size.pixel_height,
        })
    }

    pub async fn send_input(&mut self, data: Vec<u8>) -> io::Result<()> {
        self.bridge.send_input(data).await
    }

    pub async fn recv_event(&mut self) -> Option<PtyIoEvent> {
        self.bridge.recv_event().await
    }

    /// Transfer PTY events to an independent forwarding task.
    pub fn take_event_receiver(&mut self) -> io::Result<mpsc::Receiver<PtyIoEvent>> {
        self.bridge.take_event_receiver()
    }

    pub fn close(&mut self) -> io::Result<Option<ExitStatus>> {
        self.bridge.shutdown(&mut self.pty)
    }
}

/// Manages Shell sessions and their native PTY processes.
///
/// One manager belongs to one authenticated MySSH connection.
pub struct ShellSessionManager {
    pty_manager: PtyManager,
    sessions: HashMap<u128, ShellSession>,
}

impl Default for ShellSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ShellSessionManager {
    pub fn new() -> Self {
        Self {
            pty_manager: PtyManager::new(),
            sessions: HashMap::new(),
        }
    }

    /// Handle a client's SessionOpen request.
    ///
    /// Shell requests create a PTY and receive a Host-assigned session ID.
    /// FileTransfer is explicitly unsupported until Stage 06.
    pub fn accept_open_request(
        &mut self,
        core_sessions: &mut SessionManager,
        request: &Frame,
    ) -> io::Result<Frame> {
        if request.header.kind != MessageKind::SessionOpen {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Expected SessionOpen frame",
            ));
        }

        if request.header.session_id != 0 || request.header.request_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SessionOpen header",
            ));
        }

        let payload = SessionOpenPayload::decode(&request.payload)?;

        if payload.session_type == SessionType::FileTransfer {
            return Self::build_response(
                SessionOpenStatus::Unsupported,
                0,
                request.header.request_id,
            );
        }

        // Create the PTY before allocating a Core session.
        let mut pty = match self.pty_manager.spawn_default_shell(DEFAULT_PTY_SIZE) {
            Ok(pty) => pty,
            Err(_) => {
                return Self::build_response(
                    SessionOpenStatus::Rejected,
                    0,
                    request.header.request_id,
                );
            }
        };

        let bridge = match PtyIoBridge::new(&mut pty) {
            Ok(bridge) => bridge,
            Err(_) => {
                let _ = pty.close();
                return Self::build_response(
                    SessionOpenStatus::Rejected,
                    0,
                    request.header.request_id,
                );
            }
        };

        let session = match core_sessions.open(SessionKind::Shell) {
            Ok(session) => session,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let mut bridge = bridge;
                let _ = bridge.shutdown(&mut pty);
                return Self::build_response(
                    SessionOpenStatus::Rejected,
                    0,
                    request.header.request_id,
                );
            }
            Err(error) => {
                let mut bridge = bridge;
                let _ = bridge.shutdown(&mut pty);
                return Err(error);
            }
        };

        let session_id = session.id;

        self.sessions.insert(
            session_id,
            ShellSession {
                session,
                pty,
                bridge,
            },
        );

        match Self::build_response(
            SessionOpenStatus::Accepted,
            session_id,
            request.header.request_id,
        ) {
            Ok(response) => Ok(response),
            Err(error) => {
                self.close(core_sessions, session_id)?;
                Err(error)
            }
        }
    }

    fn build_response(
        status: SessionOpenStatus,
        session_id: u128,
        request_id: u64,
    ) -> io::Result<Frame> {
        let payload = SessionOpenedPayload { status };

        Frame::new(
            MessageKind::SessionOpened,
            session_id,
            request_id,
            payload.encode(),
        )
    }

    /// Get a Shell session by ID.
    pub fn get(&self, session_id: u128) -> Option<&ShellSession> {
        self.sessions.get(&session_id)
    }

    /// Get a mutable Shell session by ID.
    pub fn get_mut(&mut self, session_id: u128) -> Option<&mut ShellSession> {
        self.sessions.get_mut(&session_id)
    }

    /// Transfer a session's PTY event receiver to its forwarding task.
    pub fn take_event_receiver(
        &mut self,
        session_id: u128,
    ) -> io::Result<mpsc::Receiver<PtyIoEvent>> {
        let shell = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Unknown Shell session"))?;

        shell.take_event_receiver()
    }

    /// Close a Shell session and remove its shared Core session.
    pub fn close(
        &mut self,
        core_sessions: &mut SessionManager,
        session_id: u128,
    ) -> io::Result<Option<ExitStatus>> {
        let Some(mut shell) = self.sessions.remove(&session_id) else {
            return Ok(None);
        };

        core_sessions.close(session_id);
        shell.close()
    }

    /// Close every Shell session.
    ///
    /// Cleanup continues even if one PTY reports an error.
    /// The first error is returned after all sessions have been processed.
    pub fn close_all(&mut self, core_sessions: &mut SessionManager) -> io::Result<usize> {
        let sessions: Vec<_> = self.sessions.drain().collect();
        let count = sessions.len();
        let mut first_error = None;

        for (session_id, mut shell) in sessions {
            core_sessions.close(session_id);

            if let Err(error) = shell.close() {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }

        if let Some(error) = first_error {
            return Err(error);
        }

        Ok(count)
    }

    pub fn contains(&self, session_id: u128) -> bool {
        self.sessions.contains_key(&session_id)
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myssh_protocol::{SessionOpenPayload, SessionOpenedPayload};

    fn open_request(session_type: SessionType, request_id: u64) -> Frame {
        Frame::new(
            MessageKind::SessionOpen,
            0,
            request_id,
            SessionOpenPayload { session_type }.encode(),
        )
        .unwrap()
    }

    #[test]
    fn file_transfer_is_rejected_as_unsupported() {
        let mut manager = ShellSessionManager::new();
        let mut core_sessions = SessionManager::new();
        let request = open_request(SessionType::FileTransfer, 7);

        let response = manager
            .accept_open_request(&mut core_sessions, &request)
            .unwrap();
        let payload = SessionOpenedPayload::decode(&response.payload).unwrap();

        assert_eq!(response.header.kind, MessageKind::SessionOpened);
        assert_eq!(response.header.session_id, 0);
        assert_eq!(response.header.request_id, 7);
        assert_eq!(payload.status, SessionOpenStatus::Unsupported);
        assert!(manager.is_empty());
    }

    #[test]
    fn shell_session_can_be_opened_and_closed() {
        let mut manager = ShellSessionManager::new();
        let mut core_sessions = SessionManager::new();
        let request = open_request(SessionType::Shell, 11);

        let response = manager
            .accept_open_request(&mut core_sessions, &request)
            .unwrap();
        let payload = SessionOpenedPayload::decode(&response.payload).unwrap();

        assert_eq!(payload.status, SessionOpenStatus::Accepted);
        assert_ne!(response.header.session_id, 0);
        assert_eq!(response.header.request_id, 11);
        assert_eq!(manager.len(), 1);

        let session_id = response.header.session_id;
        assert!(manager.contains(session_id));
        assert!(manager.get(session_id).is_some());

        let _status = manager.close(&mut core_sessions, session_id).unwrap();

        assert!(!manager.contains(session_id));
        assert!(manager.is_empty());
    }

    #[test]
    fn invalid_open_header_is_rejected() {
        let mut manager = ShellSessionManager::new();
        let mut core_sessions = SessionManager::new();

        let request = Frame::new(
            MessageKind::SessionOpen,
            99,
            1,
            SessionOpenPayload {
                session_type: SessionType::Shell,
            }
            .encode(),
        )
        .unwrap();

        let result = manager.accept_open_request(&mut core_sessions, &request);

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(manager.is_empty());
    }

    #[test]
    fn close_unknown_session_is_safe() {
        let mut manager = ShellSessionManager::new();
        let mut core_sessions = SessionManager::new();

        assert!(manager.close(&mut core_sessions, 999).unwrap().is_none());
        assert!(manager.is_empty());
    }

    #[test]
    fn close_all_cleans_up_sessions() {
        let mut manager = ShellSessionManager::new();
        let mut core_sessions = SessionManager::new();

        let first = manager
            .accept_open_request(&mut core_sessions, &open_request(SessionType::Shell, 1))
            .unwrap();

        let second = manager
            .accept_open_request(&mut core_sessions, &open_request(SessionType::Shell, 2))
            .unwrap();

        assert_eq!(manager.len(), 2);

        let closed = manager.close_all(&mut core_sessions).unwrap();

        assert_eq!(closed, 2);
        assert!(manager.is_empty());

        assert!(!manager.contains(first.header.session_id));
        assert!(!manager.contains(second.header.session_id));
    }
}
