use std::collections::{HashMap, HashSet};
use std::io;

use myssh_protocol::{
    read_frame, write_frame, Frame, MessageKind, SessionClosePayload, SessionOpenPayload,
    SessionOpenStatus, SessionOpenedPayload, SessionType,
};
use myssh_transport::BoxedStream;

/// A MySSH connection after TLS and client authentication.
///
/// Core only sees an opaque bidirectional stream.
/// It does not depend on a specific transport implementation.
pub struct Connection {
    stream: BoxedStream,
    next_request_id: u64,
}

impl Connection {
    /// Create a connection from an already authenticated stream.
    pub fn new(stream: BoxedStream) -> Self {
        Self {
            stream,
            next_request_id: 1,
        }
    }

    /// Send one protocol frame and automatically assign a request ID.
    pub async fn send(
        &mut self,
        kind: MessageKind,
        session_id: u128,
        payload: Vec<u8>,
    ) -> io::Result<u64> {
        let request_id = self.next_request_id;

        self.next_request_id = self.next_request_id.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "MySSH request ID space exhausted")
        })?;

        self.send_with_request_id(kind, session_id, request_id, payload)
            .await?;

        Ok(request_id)
    }

    /// Send a frame using an explicitly supplied request ID.
    ///
    /// Useful for responses that must echo the request ID received
    /// from the remote peer.
    pub async fn send_with_request_id(
        &mut self,
        kind: MessageKind,
        session_id: u128,
        request_id: u64,
        payload: Vec<u8>,
    ) -> io::Result<()> {
        let frame = Frame::new(kind, session_id, request_id, payload)?;
        write_frame(&mut self.stream, &frame).await
    }

    /// Receive one complete protocol frame.
    pub async fn receive(&mut self) -> io::Result<Frame> {
        read_frame(&mut self.stream).await
    }

    /// Client: request a new session from the Host.
    ///
    /// Returns Some(session) when accepted, or None when rejected.
    pub async fn open_session(
        &mut self,
        manager: &mut SessionManager,
        kind: SessionKind,
    ) -> io::Result<Option<Session>> {
        let payload = SessionOpenPayload {
            session_type: kind.into(),
        };

        let request_id = self
            .send(MessageKind::SessionOpen, 0, payload.encode())
            .await?;

        let response = self.receive().await?;

        let status = manager.handle_open_response(&response, request_id, kind)?;

        match status {
            SessionOpenStatus::Accepted => Ok(manager.get(response.header.session_id).cloned()),
            SessionOpenStatus::Rejected | SessionOpenStatus::Unsupported => Ok(None),
        }
    }

    /// Host: receive a SessionOpen request and respond to the Client.
    ///
    /// The response echoes the request ID and uses the Host-assigned
    /// session ID.
    pub async fn accept_session_open(
        &mut self,
        manager: &mut SessionManager,
    ) -> io::Result<SessionOpenStatus> {
        let request = self.receive().await?;
        let response = manager.handle_open_request(&request)?;

        let status = SessionOpenedPayload::decode(&response.payload)?.status;

        self.send_with_request_id(
            response.header.kind,
            response.header.session_id,
            response.header.request_id,
            response.payload,
        )
        .await?;

        Ok(status)
    }

    /// Send a SessionClose notification and remove the local session
    /// only after the frame has been written successfully.
    pub async fn close_session(
        &mut self,
        manager: &mut SessionManager,
        session_id: u128,
    ) -> io::Result<Session> {
        if !manager.contains(session_id) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Cannot close an unknown MySSH session",
            ));
        }

        self.send(
            MessageKind::SessionClose,
            session_id,
            SessionClosePayload.encode(),
        )
        .await?;

        manager.close(session_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "MySSH session disappeared during close",
            )
        })
    }

    /// Receive and process a SessionClose notification from the peer.
    pub async fn receive_session_close(
        &mut self,
        manager: &mut SessionManager,
    ) -> io::Result<Session> {
        let frame = self.receive().await?;
        manager.handle_close_notification(&frame)
    }

    /// Recover the underlying stream.
    pub fn into_stream(self) -> BoxedStream {
        self.stream
    }
}

/// Maximum number of active sessions per connection.
pub const MAX_ACTIVE_SESSIONS: usize = 1024;

/// Identifies the purpose of a logical MySSH session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    Shell,
    FileTransfer,
}

impl From<SessionType> for SessionKind {
    fn from(value: SessionType) -> Self {
        match value {
            SessionType::Shell => Self::Shell,
            SessionType::FileTransfer => Self::FileTransfer,
        }
    }
}

impl From<SessionKind> for SessionType {
    fn from(value: SessionKind) -> Self {
        match value {
            SessionKind::Shell => Self::Shell,
            SessionKind::FileTransfer => Self::FileTransfer,
        }
    }
}

/// A session managed by one MySSH connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: u128,
    pub kind: SessionKind,
}

/// Manages logical sessions belonging to one connection.
///
/// Session IDs are scoped to this manager/connection.
#[derive(Debug)]
pub struct SessionManager {
    next_session_id: u128,
    sessions: HashMap<u128, Session>,
    used_session_ids: HashSet<u128>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            next_session_id: 1,
            sessions: HashMap::new(),
            used_session_ids: HashSet::new(),
        }
    }

    fn ensure_capacity(&self) -> io::Result<()> {
        if self.sessions.len() >= MAX_ACTIVE_SESSIONS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Maximum active MySSH sessions reached",
            ));
        }

        Ok(())
    }

    /// Allocate and register a new local session.
    pub fn open(&mut self, kind: SessionKind) -> io::Result<Session> {
        self.ensure_capacity()?;

        let id = self.next_session_id;

        if id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "MySSH session ID space exhausted",
            ));
        }

        let next_id = id.checked_add(1).unwrap_or(0);

        if self.used_session_ids.contains(&id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "MySSH session ID has already been used",
            ));
        }

        let session = Session { id, kind };

        self.sessions.insert(id, session.clone());
        self.used_session_ids.insert(id);
        self.next_session_id = next_id;

        Ok(session)
    }

    /// Register a session whose ID was assigned by the remote peer.
    ///
    /// Zero IDs, duplicate IDs and registrations beyond the session limit
    /// are rejected.
    pub fn register_remote(&mut self, session_id: u128, kind: SessionKind) -> io::Result<Session> {
        if session_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Session ID zero is reserved",
            ));
        }

        self.ensure_capacity()?;

        if self.used_session_ids.contains(&session_id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "MySSH session ID has already been used",
            ));
        }

        let session = Session {
            id: session_id,
            kind,
        };

        self.sessions.insert(session_id, session.clone());
        self.used_session_ids.insert(session_id);

        // Keep locally allocated IDs above IDs already registered here.
        if self.next_session_id != 0 && session_id >= self.next_session_id {
            self.next_session_id = session_id.checked_add(1).unwrap_or(0);
        }

        Ok(session)
    }

    /// Process a SessionOpen request on the Host side.
    ///
    /// The Host allocates the session ID and echoes the request ID.
    /// A capacity limit produces a Rejected response with session_id = 0.
    pub fn handle_open_request(&mut self, request: &Frame) -> io::Result<Frame> {
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
        let kind = SessionKind::from(payload.session_type);

        let (status, session_id) = match self.open(kind) {
            Ok(session) => (SessionOpenStatus::Accepted, session.id),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                (SessionOpenStatus::Rejected, 0)
            }
            Err(error) => return Err(error),
        };

        let response = SessionOpenedPayload { status };

        Frame::new(
            MessageKind::SessionOpened,
            session_id,
            request.header.request_id,
            response.encode(),
        )
    }

    /// Process a SessionOpened response on the Client side.
    ///
    /// The response must match the original request ID and expected session
    /// kind. Accepted sessions are registered using the Host-assigned ID.
    pub fn handle_open_response(
        &mut self,
        response: &Frame,
        expected_request_id: u64,
        expected_kind: SessionKind,
    ) -> io::Result<SessionOpenStatus> {
        if response.header.kind != MessageKind::SessionOpened {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Expected SessionOpened frame",
            ));
        }

        if expected_request_id == 0 || response.header.request_id != expected_request_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SessionOpened request ID mismatch",
            ));
        }

        let payload = SessionOpenedPayload::decode(&response.payload)?;

        match payload.status {
            SessionOpenStatus::Accepted => {
                if response.header.session_id == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Accepted session must have a nonzero ID",
                    ));
                }

                self.register_remote(response.header.session_id, expected_kind)?;
            }
            SessionOpenStatus::Rejected | SessionOpenStatus::Unsupported => {
                if response.header.session_id != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Rejected session must have ID zero",
                    ));
                }
            }
        }

        Ok(payload.status)
    }

    /// Build a SessionClose notification for an active session.
    ///
    /// The caller should remove the local session only after the frame
    /// has been successfully sent.
    pub fn build_close_frame(&self, session_id: u128, request_id: u64) -> io::Result<Frame> {
        if request_id == 0 || !self.contains(session_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid SessionClose request",
            ));
        }

        Frame::new(
            MessageKind::SessionClose,
            session_id,
            request_id,
            SessionClosePayload.encode(),
        )
    }

    /// Process a received SessionClose notification.
    pub fn handle_close_notification(&mut self, frame: &Frame) -> io::Result<Session> {
        if frame.header.kind != MessageKind::SessionClose {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Expected SessionClose frame",
            ));
        }

        if frame.header.session_id == 0 || frame.header.request_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SessionClose header",
            ));
        }

        SessionClosePayload::decode(&frame.payload)?;

        self.close(frame.header.session_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "SessionClose references an unknown session",
            )
        })
    }

    /// Look up an active session.
    pub fn get(&self, session_id: u128) -> Option<&Session> {
        self.sessions.get(&session_id)
    }

    /// Close and remove an active session.
    pub fn close(&mut self, session_id: u128) -> Option<Session> {
        self.sessions.remove(&session_id)
    }

    /// Return the number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Check whether a session ID is currently active.
    pub fn contains(&self, session_id: u128) -> bool {
        self.sessions.contains_key(&session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use myssh_protocol::MessageKind;
    use tokio::io::duplex;

    #[tokio::test]
    async fn connection_sends_frame_with_incrementing_request_ids() {
        let (client_io, mut peer) = duplex(4096);

        let mut connection = Connection::new(Box::new(client_io));

        let first_id = connection
            .send(MessageKind::Ping, 0, b"first".to_vec())
            .await
            .unwrap();

        let second_id = connection
            .send(MessageKind::Ping, 0, b"second".to_vec())
            .await
            .unwrap();

        assert_eq!(first_id, 1);
        assert_eq!(second_id, 2);

        let first = read_frame_for_test(&mut peer).await;
        let second = read_frame_for_test(&mut peer).await;

        assert_eq!(first.header.request_id, 1);
        assert_eq!(first.payload, b"first");
        assert_eq!(second.header.request_id, 2);
        assert_eq!(second.payload, b"second");
    }

    async fn read_frame_for_test<R>(reader: &mut R) -> Frame
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        myssh_protocol::read_frame(reader).await.unwrap()
    }

    #[tokio::test]
    async fn connection_receives_frame() {
        let (client_io, mut peer) = duplex(4096);

        let mut connection = Connection::new(Box::new(client_io));

        let frame = Frame::new(MessageKind::Pong, 0, 77, b"response".to_vec()).unwrap();

        write_frame_for_test(&mut peer, &frame).await;

        let received = connection.receive().await.unwrap();

        assert_eq!(received.header.kind, MessageKind::Pong);
        assert_eq!(received.header.request_id, 77);
        assert_eq!(received.payload, b"response");
    }

    async fn write_frame_for_test<W>(writer: &mut W, frame: &Frame)
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        myssh_protocol::write_frame(writer, frame).await.unwrap();
    }

    #[test]
    fn session_manager_opens_and_finds_sessions() {
        let mut manager = SessionManager::new();

        let shell = manager.open(SessionKind::Shell).unwrap();
        let transfer = manager.open(SessionKind::FileTransfer).unwrap();

        assert_ne!(shell.id, transfer.id);
        assert_eq!(manager.len(), 2);
        assert_eq!(manager.get(shell.id), Some(&shell));
        assert_eq!(manager.get(transfer.id), Some(&transfer));
    }

    #[test]
    fn session_manager_closes_sessions() {
        let mut manager = SessionManager::new();

        let session = manager.open(SessionKind::Shell).unwrap();

        let session_id = session.id;
        let closed = manager.close(session_id);

        assert_eq!(closed, Some(session));
        assert!(!manager.contains(session_id));
        assert!(manager.is_empty());
    }

    #[test]
    fn closing_unknown_session_returns_none() {
        let mut manager = SessionManager::new();

        assert!(manager.close(999).is_none());
    }

    #[test]
    fn session_ids_are_not_reused_after_close() {
        let mut manager = SessionManager::new();

        let first = manager.open(SessionKind::Shell).unwrap();
        manager.close(first.id);

        let second = manager.open(SessionKind::FileTransfer).unwrap();

        assert_ne!(first.id, second.id);
    }
}

#[cfg(test)]
mod remote_session_tests {
    use super::*;

    #[test]
    fn registers_remote_session() {
        let mut manager = SessionManager::new();

        let session = manager.register_remote(500, SessionKind::Shell).unwrap();

        assert_eq!(session.id, 500);
        assert_eq!(session.kind, SessionKind::Shell);
        assert_eq!(manager.get(500), Some(&session));
    }

    #[test]
    fn rejects_zero_remote_session_id() {
        let mut manager = SessionManager::new();

        let result = manager.register_remote(0, SessionKind::Shell);

        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_duplicate_remote_session_id() {
        let mut manager = SessionManager::new();

        manager.register_remote(100, SessionKind::Shell).unwrap();

        let result = manager.register_remote(100, SessionKind::FileTransfer);

        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn local_ids_advance_past_registered_remote_ids() {
        let mut manager = SessionManager::new();

        manager.register_remote(500, SessionKind::Shell).unwrap();

        let local = manager.open(SessionKind::FileTransfer).unwrap();

        assert_eq!(local.id, 501);
    }

    #[test]
    fn session_kind_protocol_conversion() {
        assert_eq!(SessionKind::from(SessionType::Shell), SessionKind::Shell);

        assert_eq!(
            SessionKind::from(SessionType::FileTransfer),
            SessionKind::FileTransfer
        );

        assert_eq!(SessionType::from(SessionKind::Shell), SessionType::Shell);

        assert_eq!(
            SessionType::from(SessionKind::FileTransfer),
            SessionType::FileTransfer
        );
    }

    #[test]
    fn default_session_manager_is_ready() {
        let mut manager = SessionManager::default();

        let session = manager.open(SessionKind::Shell).unwrap();

        assert_eq!(session.id, 1);
    }

    #[test]
    fn enforces_maximum_active_sessions() {
        let mut manager = SessionManager::new();

        for id in 1..=MAX_ACTIVE_SESSIONS as u128 {
            manager.register_remote(id, SessionKind::Shell).unwrap();
        }

        assert_eq!(manager.len(), MAX_ACTIVE_SESSIONS);

        let result = manager.register_remote(MAX_ACTIVE_SESSIONS as u128 + 1, SessionKind::Shell);

        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }
}

#[cfg(test)]
mod session_control_tests {
    use super::*;

    #[test]
    fn host_accepts_open_and_echoes_request_id() {
        let mut host = SessionManager::new();

        let payload = SessionOpenPayload {
            session_type: SessionType::Shell,
        };

        let request = Frame::new(MessageKind::SessionOpen, 0, 42, payload.encode()).unwrap();

        let response = host.handle_open_request(&request).unwrap();

        assert_eq!(response.header.kind, MessageKind::SessionOpened);
        assert_eq!(response.header.request_id, 42);
        assert_ne!(response.header.session_id, 0);

        let decoded = SessionOpenedPayload::decode(&response.payload).unwrap();
        assert_eq!(decoded.status, SessionOpenStatus::Accepted);
        assert!(host.contains(response.header.session_id));
    }

    #[test]
    fn client_registers_host_assigned_session_id() {
        let mut client = SessionManager::new();

        let response = Frame::new(
            MessageKind::SessionOpened,
            700,
            55,
            SessionOpenedPayload {
                status: SessionOpenStatus::Accepted,
            }
            .encode(),
        )
        .unwrap();

        let status = client
            .handle_open_response(&response, 55, SessionKind::Shell)
            .unwrap();

        assert_eq!(status, SessionOpenStatus::Accepted);
        assert!(client.contains(700));
        assert_eq!(client.get(700).unwrap().kind, SessionKind::Shell);
    }

    #[test]
    fn client_rejects_mismatched_request_id() {
        let mut client = SessionManager::new();

        let response = Frame::new(
            MessageKind::SessionOpened,
            700,
            56,
            SessionOpenedPayload {
                status: SessionOpenStatus::Accepted,
            }
            .encode(),
        )
        .unwrap();

        assert!(client
            .handle_open_response(&response, 55, SessionKind::Shell)
            .is_err());

        assert!(client.is_empty());
    }

    #[test]
    fn rejected_open_must_have_zero_session_id() {
        let mut client = SessionManager::new();

        let response = Frame::new(
            MessageKind::SessionOpened,
            123,
            55,
            SessionOpenedPayload {
                status: SessionOpenStatus::Rejected,
            }
            .encode(),
        )
        .unwrap();

        assert!(client
            .handle_open_response(&response, 55, SessionKind::Shell)
            .is_err());
    }

    #[test]
    fn host_rejects_invalid_open_header() {
        let mut host = SessionManager::new();

        let request = Frame::new(
            MessageKind::SessionOpen,
            99,
            42,
            SessionOpenPayload {
                session_type: SessionType::Shell,
            }
            .encode(),
        )
        .unwrap();

        assert!(host.handle_open_request(&request).is_err());
        assert!(host.is_empty());
    }

    #[test]
    fn close_notification_removes_session() {
        let mut manager = SessionManager::new();
        let session = manager.open(SessionKind::Shell).unwrap();

        let frame = manager.build_close_frame(session.id, 88).unwrap();
        let closed = manager.handle_close_notification(&frame).unwrap();

        assert_eq!(closed, session);
        assert!(!manager.contains(session.id));
    }

    #[test]
    fn closed_session_id_cannot_be_registered_again() {
        let mut manager = SessionManager::new();

        let session = manager.register_remote(900, SessionKind::Shell).unwrap();
        manager.close(session.id);

        let result = manager.register_remote(900, SessionKind::Shell);

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn close_unknown_session_is_rejected() {
        let mut manager = SessionManager::new();

        let frame = Frame::new(
            MessageKind::SessionClose,
            1234,
            88,
            SessionClosePayload.encode(),
        )
        .unwrap();

        assert_eq!(
            manager
                .handle_close_notification(&frame)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }
}

#[cfg(test)]
mod connection_session_integration_tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn client_and_host_open_session_over_connection() {
        let (client_io, host_io) = duplex(4096);

        let mut client = Connection::new(Box::new(client_io));
        let mut host = Connection::new(Box::new(host_io));

        let mut client_sessions = SessionManager::new();
        let mut host_sessions = SessionManager::new();

        let (client_result, host_result) = tokio::join!(
            client.open_session(&mut client_sessions, SessionKind::Shell,),
            host.accept_session_open(&mut host_sessions),
        );

        let client_session = client_result.unwrap().unwrap();
        let host_status = host_result.unwrap();

        assert_eq!(host_status, SessionOpenStatus::Accepted);
        assert_eq!(client_session.kind, SessionKind::Shell);

        assert_eq!(
            client_session.id,
            host_sessions.get(client_session.id).unwrap().id
        );

        assert!(client_sessions.contains(client_session.id));
        assert!(host_sessions.contains(client_session.id));
    }

    #[tokio::test]
    async fn client_and_host_close_session_over_connection() {
        let (client_io, host_io) = duplex(4096);

        let mut client = Connection::new(Box::new(client_io));
        let mut host = Connection::new(Box::new(host_io));

        let mut client_sessions = SessionManager::new();
        let mut host_sessions = SessionManager::new();

        let (opened, _) = tokio::join!(
            client.open_session(&mut client_sessions, SessionKind::FileTransfer,),
            host.accept_session_open(&mut host_sessions),
        );

        let session = opened.unwrap().unwrap();

        let (client_closed, host_closed) = tokio::join!(
            client.close_session(&mut client_sessions, session.id),
            host.receive_session_close(&mut host_sessions),
        );

        assert_eq!(client_closed.unwrap(), session);
        assert_eq!(host_closed.unwrap(), session);

        assert!(client_sessions.is_empty());
        assert!(host_sessions.is_empty());
    }

    #[tokio::test]
    async fn close_unknown_local_session_fails() {
        let (client_io, _peer) = duplex(4096);

        let mut connection = Connection::new(Box::new(client_io));
        let mut manager = SessionManager::new();

        let result = connection.close_session(&mut manager, 999).await;

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    }
}

// ============================================================
// Split Connection I/O
// ============================================================

/// Read half of an authenticated MySSH connection.
pub struct ConnectionReader {
    stream: tokio::io::ReadHalf<BoxedStream>,
}

impl ConnectionReader {
    /// Receive one complete protocol frame.
    pub async fn receive(&mut self) -> io::Result<Frame> {
        read_frame(&mut self.stream).await
    }
}

/// Write half of an authenticated MySSH connection.
pub struct ConnectionWriter {
    stream: tokio::io::WriteHalf<BoxedStream>,
    next_request_id: u64,
}

impl ConnectionWriter {
    /// Send a frame with an automatically assigned request ID.
    pub async fn send(
        &mut self,
        kind: MessageKind,
        session_id: u128,
        payload: Vec<u8>,
    ) -> io::Result<u64> {
        let request_id = self.next_request_id;

        self.next_request_id = self.next_request_id.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "MySSH request ID space exhausted")
        })?;

        self.send_with_request_id(kind, session_id, request_id, payload)
            .await?;

        Ok(request_id)
    }

    /// Send a frame using an explicit request ID.
    pub async fn send_with_request_id(
        &mut self,
        kind: MessageKind,
        session_id: u128,
        request_id: u64,
        payload: Vec<u8>,
    ) -> io::Result<()> {
        let frame = Frame::new(kind, session_id, request_id, payload)?;

        write_frame(&mut self.stream, &frame).await
    }
}

impl Connection {
    /// Split the connection into independent read and write halves.
    ///
    /// This allows terminal input and output to proceed independently.
    pub fn into_split(self) -> (ConnectionReader, ConnectionWriter) {
        let (reader, writer) = tokio::io::split(self.stream);

        (
            ConnectionReader { stream: reader },
            ConnectionWriter {
                stream: writer,
                next_request_id: self.next_request_id,
            },
        )
    }
}

#[cfg(test)]
mod split_connection_tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn split_connection_sends_and_receives_independently() {
        let (local, mut peer) = duplex(4096);

        let connection = Connection::new(Box::new(local));
        let (mut reader, mut writer) = connection.into_split();

        let request_id = writer
            .send(MessageKind::SessionData, 77, b"terminal input".to_vec())
            .await
            .unwrap();

        assert_eq!(request_id, 1);

        let received = read_frame(&mut peer).await.unwrap();

        assert_eq!(received.header.kind, MessageKind::SessionData);
        assert_eq!(received.header.session_id, 77);
        assert_eq!(received.payload, b"terminal input");

        let response =
            Frame::new(MessageKind::SessionData, 77, 2, b"terminal output".to_vec()).unwrap();

        write_frame(&mut peer, &response).await.unwrap();

        let received = reader.receive().await.unwrap();

        assert_eq!(received.header.kind, MessageKind::SessionData);
        assert_eq!(received.header.session_id, 77);
        assert_eq!(received.payload, b"terminal output");
    }

    #[tokio::test]
    async fn split_writer_increments_request_ids() {
        let (local, mut peer) = duplex(4096);

        let connection = Connection::new(Box::new(local));
        let (_, mut writer) = connection.into_split();

        assert_eq!(writer.send(MessageKind::Ping, 0, vec![]).await.unwrap(), 1);

        assert_eq!(writer.send(MessageKind::Ping, 0, vec![]).await.unwrap(), 2);

        assert_eq!(read_frame(&mut peer).await.unwrap().header.request_id, 1);
        assert_eq!(read_frame(&mut peer).await.unwrap().header.request_id, 2);
    }
}
