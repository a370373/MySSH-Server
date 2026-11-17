use std::io;

pub const MAGIC: [u8; 4] = *b"MYSH";

pub const PROTOCOL_VERSION: u16 = 1;

pub const HEADER_SIZE: usize = 40;

pub const MAX_PAYLOAD_SIZE: u32 = 1024 * 1024;

pub const FILE_CHUNK_SIZE: usize = 256 * 1024;

/// MySSH protocol message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageKind {
    AuthRequest = 1,
    AuthResponse = 2,
    AuthChallenge = 3,
    AuthProof = 4,

    SessionOpen = 10,
    SessionOpened = 11,
    SessionData = 12,
    SessionResize = 13,
    SessionClose = 14,

    FileBegin = 20,
    FileChunk = 21,
    FileEnd = 22,
    FileResponse = 23,
    FileRequest = 24,

    Ping = 30,
    Pong = 31,

    Error = 255,
}

impl TryFrom<u16> for MessageKind {
    type Error = io::Error;

    fn try_from(value: u16) -> Result<Self, io::Error> {
        match value {
            1 => Ok(Self::AuthRequest),
            2 => Ok(Self::AuthResponse),
            3 => Ok(Self::AuthChallenge),
            4 => Ok(Self::AuthProof),

            10 => Ok(Self::SessionOpen),
            11 => Ok(Self::SessionOpened),
            12 => Ok(Self::SessionData),
            13 => Ok(Self::SessionResize),
            14 => Ok(Self::SessionClose),

            20 => Ok(Self::FileBegin),
            21 => Ok(Self::FileChunk),
            22 => Ok(Self::FileEnd),
            23 => Ok(Self::FileResponse),
            24 => Ok(Self::FileRequest),

            30 => Ok(Self::Ping),
            31 => Ok(Self::Pong),

            255 => Ok(Self::Error),

            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown MySSH message type",
            )),
        }
    }
}

/// Fixed-size MySSH packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: MessageKind,
    pub flags: u16,
    pub session_id: u128,
    pub request_id: u64,
    pub payload_len: u32,
}

impl Header {
    pub fn new(
        kind: MessageKind,
        session_id: u128,
        request_id: u64,
        payload_len: u32,
    ) -> io::Result<Self> {
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Payload exceeds maximum size",
            ));
        }

        Ok(Self {
            kind,
            flags: 0,
            session_id,
            request_id,
            payload_len,
        })
    }

    /// Encode the header into exactly 40 bytes.
    pub fn encode(&self) -> io::Result<[u8; HEADER_SIZE]> {
        if self.payload_len > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Payload exceeds maximum size",
            ));
        }

        if self.flags != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unsupported header flags",
            ));
        }

        let mut buffer = [0u8; HEADER_SIZE];

        buffer[0..4].copy_from_slice(&MAGIC);
        buffer[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        buffer[6..8].copy_from_slice(&(self.kind as u16).to_be_bytes());
        buffer[8..10].copy_from_slice(&self.flags.to_be_bytes());

        // Bytes 10..12 are reserved and remain zero.

        buffer[12..28].copy_from_slice(&self.session_id.to_be_bytes());
        buffer[28..36].copy_from_slice(&self.request_id.to_be_bytes());
        buffer[36..40].copy_from_slice(&self.payload_len.to_be_bytes());

        Ok(buffer)
    }

    /// Decode and validate a 40-byte header.
    pub fn decode(buffer: &[u8; HEADER_SIZE]) -> io::Result<Self> {
        if buffer[0..4] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid MySSH magic",
            ));
        }

        let version = u16::from_be_bytes([buffer[4], buffer[5]]);

        if version != PROTOCOL_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported MySSH protocol version",
            ));
        }

        let kind_value = u16::from_be_bytes([buffer[6], buffer[7]]);

        let kind = MessageKind::try_from(kind_value)?;

        let flags = u16::from_be_bytes([buffer[8], buffer[9]]);

        if flags != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported header flags",
            ));
        }

        if buffer[10] != 0 || buffer[11] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Reserved header bytes must be zero",
            ));
        }

        let session_id = u128::from_be_bytes(buffer[12..28].try_into().unwrap());

        let request_id = u64::from_be_bytes(buffer[28..36].try_into().unwrap());

        let payload_len = u32::from_be_bytes([buffer[36], buffer[37], buffer[38], buffer[39]]);

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Payload exceeds maximum size",
            ));
        }

        Ok(Self {
            kind,
            flags,
            session_id,
            request_id,
            payload_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let original = Header::new(MessageKind::SessionData, 123456789, 42, 1024).unwrap();

        let encoded = original.encode().unwrap();
        let decoded = Header::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn header_has_correct_size() {
        let header = Header::new(MessageKind::Ping, 0, 1, 0).unwrap();

        assert_eq!(header.encode().unwrap().len(), HEADER_SIZE);
    }

    #[test]
    fn rejects_invalid_magic() {
        let buffer = [0u8; HEADER_SIZE];

        assert!(Header::decode(&buffer).is_err());
    }

    #[test]
    fn rejects_oversized_payload() {
        let result = Header::new(MessageKind::FileChunk, 1, 1, MAX_PAYLOAD_SIZE + 1);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_unknown_message_type() {
        assert!(MessageKind::try_from(999).is_err());
    }

    #[test]
    fn authentication_message_kinds_have_correct_values() {
        assert_eq!(MessageKind::AuthRequest as u16, 1);
        assert_eq!(MessageKind::AuthResponse as u16, 2);
        assert_eq!(MessageKind::AuthChallenge as u16, 3);
        assert_eq!(MessageKind::AuthProof as u16, 4);

        assert_eq!(
            MessageKind::try_from(3).unwrap(),
            MessageKind::AuthChallenge
        );
        assert_eq!(MessageKind::try_from(4).unwrap(), MessageKind::AuthProof);
    }
}

// ============================================================
// Frame I/O
// ============================================================

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A complete MySSH protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: Header,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a frame and automatically calculate payload length.
    pub fn new(
        kind: MessageKind,
        session_id: u128,
        request_id: u64,
        payload: Vec<u8>,
    ) -> io::Result<Self> {
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Payload is too large"))?;

        let header = Header::new(kind, session_id, request_id, payload_len)?;

        Ok(Self { header, payload })
    }

    /// Validate that header and payload lengths match.
    pub fn validate(&self) -> io::Result<()> {
        if self.payload.len() > MAX_PAYLOAD_SIZE as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Payload exceeds maximum size",
            ));
        }

        if self.header.payload_len as usize != self.payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Header and payload lengths do not match",
            ));
        }

        Ok(())
    }
}

/// Read one complete frame from an asynchronous stream.
///
/// The header is validated before payload memory is allocated.
pub async fn read_frame<R>(reader: &mut R) -> io::Result<Frame>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut header_buffer = [0u8; HEADER_SIZE];

    reader.read_exact(&mut header_buffer).await?;

    let header = Header::decode(&header_buffer)?;

    let payload_len = header.payload_len as usize;

    let mut payload = vec![0u8; payload_len];

    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }

    Ok(Frame { header, payload })
}

/// Write one complete frame to an asynchronous stream.
pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    frame.validate()?;

    let header_buffer = frame.header.encode()?;

    writer.write_all(&header_buffer).await?;

    if !frame.payload.is_empty() {
        writer.write_all(&frame.payload).await?;
    }

    writer.flush().await?;

    Ok(())
}

#[cfg(test)]
mod frame_tests {
    use super::*;

    use tokio::io::duplex;

    #[tokio::test]
    async fn frame_round_trip() {
        let (mut left, mut right) = duplex(4096);

        let original =
            Frame::new(MessageKind::SessionData, 123, 456, b"Hello MySSH".to_vec()).unwrap();

        write_frame(&mut left, &original).await.unwrap();

        let received = read_frame(&mut right).await.unwrap();

        assert_eq!(original, received);
    }

    #[tokio::test]
    async fn empty_payload_round_trip() {
        let (mut left, mut right) = duplex(4096);

        let original = Frame::new(MessageKind::Ping, 0, 1, Vec::new()).unwrap();

        write_frame(&mut left, &original).await.unwrap();

        let received = read_frame(&mut right).await.unwrap();

        assert_eq!(original, received);
        assert!(received.payload.is_empty());
    }

    #[tokio::test]
    async fn file_chunk_round_trip() {
        let (mut left, mut right) = duplex(512 * 1024);

        let data = vec![0x5A; FILE_CHUNK_SIZE];

        let original = Frame::new(MessageKind::FileChunk, 99, 10, data).unwrap();

        write_frame(&mut left, &original).await.unwrap();

        let received = read_frame(&mut right).await.unwrap();

        assert_eq!(original, received);
    }

    #[test]
    fn rejects_mismatched_payload_length() {
        let frame = Frame {
            header: Header::new(MessageKind::SessionData, 1, 1, 10).unwrap(),
            payload: vec![0u8; 5],
        };

        assert!(frame.validate().is_err());
    }

    #[test]
    fn rejects_oversized_payload() {
        let header = Header {
            kind: MessageKind::FileChunk,
            flags: 0,
            session_id: 1,
            request_id: 1,
            payload_len: MAX_PAYLOAD_SIZE + 1,
        };

        let frame = Frame {
            header,
            payload: Vec::new(),
        };

        assert!(frame.validate().is_err());
    }
}

// ============================================================
// Authentication Payload Codecs
// ============================================================

pub const AUTH_PAYLOAD_VERSION: u8 = 1;
pub const MAX_AUTH_USERNAME_BYTES: usize = 256;
pub const MAX_AUTH_KEY_ID_BYTES: usize = 80;

const AUTH_REQUEST_FIXED_SIZE: usize = 1;
const AUTH_CHALLENGE_FIXED_SIZE: usize = 1 + 16 + 32 + 2;
const AUTH_PROOF_FIXED_SIZE: usize = 1 + 16 + 64;
const AUTH_RESPONSE_SIZE: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequestPayload {
    pub username: String,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallengePayload {
    pub challenge_id: [u8; 16],
    pub nonce: [u8; 32],
    pub username: String,
    pub key_id: String,
    pub protocol_version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthProofPayload {
    pub challenge_id: [u8; 16],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthStatus {
    Success = 0,
    Denied = 1,
    Unsupported = 2,
    ProtocolError = 3,
}

impl TryFrom<u8> for AuthStatus {
    type Error = io::Error;

    fn try_from(value: u8) -> io::Result<Self> {
        match value {
            0 => Ok(Self::Success),
            1 => Ok(Self::Denied),
            2 => Ok(Self::Unsupported),
            3 => Ok(Self::ProtocolError),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown authentication status",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthResponsePayload {
    pub status: AuthStatus,
}

fn auth_encode_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn auth_decode_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn validate_auth_string(value: &str, max_len: usize) -> io::Result<()> {
    if value.is_empty() || value.len() > max_len {
        return Err(auth_encode_error("Invalid authentication string length"));
    }

    if value.as_bytes().contains(&0) {
        return Err(auth_encode_error("Authentication string contains NUL"));
    }

    Ok(())
}

fn encode_auth_string(output: &mut Vec<u8>, value: &str, max_len: usize) -> io::Result<()> {
    validate_auth_string(value, max_len)?;

    let len = u16::try_from(value.len())
        .map_err(|_| auth_encode_error("Authentication string is too long"))?;

    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value.as_bytes());

    Ok(())
}

struct AuthPayloadReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> AuthPayloadReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| auth_decode_error("Payload length overflow"))?;

        if end > self.data.len() {
            return Err(auth_decode_error("Truncated authentication payload"));
        }

        let result = &self.data[self.position..end];
        self.position = end;

        Ok(result)
    }

    fn read_u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> io::Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_string(&mut self, max_len: usize) -> io::Result<String> {
        let len = self.read_u16()? as usize;

        if len == 0 || len > max_len {
            return Err(auth_decode_error("Invalid authentication string length"));
        }

        let bytes = self.take(len)?;

        if bytes.contains(&0) {
            return Err(auth_decode_error("Authentication string contains NUL"));
        }

        let value = std::str::from_utf8(bytes)
            .map_err(|_| auth_decode_error("Invalid UTF-8 in authentication payload"))?;

        Ok(value.to_owned())
    }

    fn finish(self) -> io::Result<()> {
        if self.position != self.data.len() {
            return Err(auth_decode_error("Trailing authentication payload data"));
        }

        Ok(())
    }
}

fn auth_reader(data: &[u8]) -> io::Result<AuthPayloadReader<'_>> {
    if data.len() > MAX_PAYLOAD_SIZE as usize {
        return Err(auth_decode_error("Authentication payload too large"));
    }

    let mut reader = AuthPayloadReader::new(data);

    let version = reader.read_u8()?;

    if version != AUTH_PAYLOAD_VERSION {
        return Err(auth_decode_error(
            "Unsupported authentication payload version",
        ));
    }

    Ok(reader)
}

impl AuthRequestPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(
            AUTH_REQUEST_FIXED_SIZE + 4 + self.username.len() + self.key_id.len(),
        );

        output.push(AUTH_PAYLOAD_VERSION);

        encode_auth_string(&mut output, &self.username, MAX_AUTH_USERNAME_BYTES)?;

        encode_auth_string(&mut output, &self.key_id, MAX_AUTH_KEY_ID_BYTES)?;

        Ok(output)
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        let mut reader = auth_reader(data)?;

        let username = reader.read_string(MAX_AUTH_USERNAME_BYTES)?;
        let key_id = reader.read_string(MAX_AUTH_KEY_ID_BYTES)?;

        reader.finish()?;

        Ok(Self { username, key_id })
    }
}

impl AuthChallengePayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(auth_encode_error("Unsupported challenge protocol version"));
        }

        let mut output = Vec::with_capacity(
            AUTH_CHALLENGE_FIXED_SIZE + 4 + self.username.len() + self.key_id.len(),
        );

        output.push(AUTH_PAYLOAD_VERSION);
        output.extend_from_slice(&self.challenge_id);
        output.extend_from_slice(&self.nonce);
        output.extend_from_slice(&self.protocol_version.to_be_bytes());

        encode_auth_string(&mut output, &self.username, MAX_AUTH_USERNAME_BYTES)?;

        encode_auth_string(&mut output, &self.key_id, MAX_AUTH_KEY_ID_BYTES)?;

        Ok(output)
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        let mut reader = auth_reader(data)?;

        let mut challenge_id = [0u8; 16];
        challenge_id.copy_from_slice(reader.take(16)?);

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(reader.take(32)?);

        let protocol_version = reader.read_u16()?;

        if protocol_version != PROTOCOL_VERSION {
            return Err(auth_decode_error("Unsupported challenge protocol version"));
        }

        let username = reader.read_string(MAX_AUTH_USERNAME_BYTES)?;
        let key_id = reader.read_string(MAX_AUTH_KEY_ID_BYTES)?;

        reader.finish()?;

        Ok(Self {
            challenge_id,
            nonce,
            username,
            key_id,
            protocol_version,
        })
    }
}

impl AuthProofPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(AUTH_PROOF_FIXED_SIZE);

        output.push(AUTH_PAYLOAD_VERSION);
        output.extend_from_slice(&self.challenge_id);
        output.extend_from_slice(&self.signature);

        output
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        let mut reader = auth_reader(data)?;

        let mut challenge_id = [0u8; 16];
        challenge_id.copy_from_slice(reader.take(16)?);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(reader.take(64)?);

        reader.finish()?;

        Ok(Self {
            challenge_id,
            signature,
        })
    }
}

impl AuthResponsePayload {
    pub fn encode(&self) -> Vec<u8> {
        vec![AUTH_PAYLOAD_VERSION, self.status as u8]
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        if data.len() != AUTH_RESPONSE_SIZE {
            return Err(auth_decode_error("Invalid authentication response size"));
        }

        if data[0] != AUTH_PAYLOAD_VERSION {
            return Err(auth_decode_error(
                "Unsupported authentication payload version",
            ));
        }

        Ok(Self {
            status: AuthStatus::try_from(data[1])?,
        })
    }
}

// ============================================================
// Authentication Payload Tests
// ============================================================

#[cfg(test)]
mod auth_payload_tests {
    use super::*;

    fn sample_request() -> AuthRequestPayload {
        AuthRequestPayload {
            username: "admin".to_string(),
            key_id: format!("ed25519:{}", "a".repeat(64)),
        }
    }

    fn sample_challenge() -> AuthChallengePayload {
        AuthChallengePayload {
            challenge_id: [1u8; 16],
            nonce: [2u8; 32],
            username: "admin".to_string(),
            key_id: format!("ed25519:{}", "b".repeat(64)),
            protocol_version: PROTOCOL_VERSION,
        }
    }

    #[test]
    fn auth_request_round_trip() {
        let original = sample_request();
        let encoded = original.encode().unwrap();
        let decoded = AuthRequestPayload::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn auth_challenge_round_trip() {
        let original = sample_challenge();
        let encoded = original.encode().unwrap();
        let decoded = AuthChallengePayload::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn auth_proof_round_trip() {
        let original = AuthProofPayload {
            challenge_id: [3u8; 16],
            signature: [4u8; 64],
        };

        let encoded = original.encode();
        let decoded = AuthProofPayload::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn auth_response_round_trip() {
        for status in [
            AuthStatus::Success,
            AuthStatus::Denied,
            AuthStatus::Unsupported,
            AuthStatus::ProtocolError,
        ] {
            let original = AuthResponsePayload { status };
            let decoded = AuthResponsePayload::decode(&original.encode()).unwrap();

            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn rejects_truncated_request() {
        assert!(AuthRequestPayload::decode(&[AUTH_PAYLOAD_VERSION]).is_err());
    }

    #[test]
    fn rejects_invalid_utf8() {
        let data = [AUTH_PAYLOAD_VERSION, 0, 1, 0xff, 0, 1, b'x'];

        assert!(AuthRequestPayload::decode(&data).is_err());
    }

    #[test]
    fn rejects_trailing_request_data() {
        let mut data = sample_request().encode().unwrap();
        data.push(0);

        assert!(AuthRequestPayload::decode(&data).is_err());
    }

    #[test]
    fn rejects_oversized_username() {
        let request = AuthRequestPayload {
            username: "a".repeat(MAX_AUTH_USERNAME_BYTES + 1),
            key_id: "key".to_string(),
        };

        assert!(request.encode().is_err());
    }

    #[test]
    fn rejects_unknown_auth_status() {
        assert!(AuthResponsePayload::decode(&[AUTH_PAYLOAD_VERSION, 99,]).is_err());
    }

    #[test]
    fn rejects_wrong_challenge_protocol_version() {
        let mut challenge = sample_challenge();
        challenge.protocol_version = PROTOCOL_VERSION + 1;

        assert!(challenge.encode().is_err());
    }

    #[test]
    fn rejects_wrong_payload_version() {
        assert!(AuthResponsePayload::decode(&[99, 0]).is_err());
    }

    #[test]
    fn rejects_truncated_proof() {
        assert!(AuthProofPayload::decode(&[AUTH_PAYLOAD_VERSION; 20]).is_err());
    }
}

// ============================================================
// Session payloads
// ============================================================

pub const SESSION_PAYLOAD_VERSION: u8 = 1;

/// Logical session types supported by the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionType {
    Shell = 1,
    FileTransfer = 2,
}

impl TryFrom<u8> for SessionType {
    type Error = io::Error;

    fn try_from(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Shell),
            2 => Ok(Self::FileTransfer),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown MySSH session type",
            )),
        }
    }
}

/// Client request to open a logical session.
///
/// Wire format: [version: u8, session_type: u8]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionOpenPayload {
    pub session_type: SessionType,
}

impl SessionOpenPayload {
    pub fn encode(&self) -> Vec<u8> {
        vec![SESSION_PAYLOAD_VERSION, self.session_type as u8]
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SessionOpen payload length",
            ));
        }

        if payload[0] != SESSION_PAYLOAD_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported SessionOpen payload version",
            ));
        }

        Ok(Self {
            session_type: SessionType::try_from(payload[1])?,
        })
    }
}

/// Result of a SessionOpen request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionOpenStatus {
    Accepted = 1,
    Rejected = 2,
    Unsupported = 3,
}

impl TryFrom<u8> for SessionOpenStatus {
    type Error = io::Error;

    fn try_from(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::Unsupported),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown SessionOpen status",
            )),
        }
    }
}

/// Host response to a SessionOpen request.
///
/// Wire format: [version: u8, status: u8]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionOpenedPayload {
    pub status: SessionOpenStatus,
}

impl SessionOpenedPayload {
    pub fn encode(&self) -> Vec<u8> {
        vec![SESSION_PAYLOAD_VERSION, self.status as u8]
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SessionOpened payload length",
            ));
        }

        if payload[0] != SESSION_PAYLOAD_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported SessionOpened payload version",
            ));
        }

        Ok(Self {
            status: SessionOpenStatus::try_from(payload[1])?,
        })
    }
}

/// Session close notification.
///
/// Wire format: [version: u8]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionClosePayload;

impl SessionClosePayload {
    pub fn encode(&self) -> Vec<u8> {
        vec![SESSION_PAYLOAD_VERSION]
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SessionClose payload length",
            ));
        }

        if payload[0] != SESSION_PAYLOAD_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported SessionClose payload version",
            ));
        }

        Ok(Self)
    }
}

#[cfg(test)]
mod session_payload_tests {
    use super::*;

    #[test]
    fn session_open_payload_round_trip() {
        let original = SessionOpenPayload {
            session_type: SessionType::Shell,
        };

        let decoded = SessionOpenPayload::decode(&original.encode()).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn session_open_file_transfer_round_trip() {
        let original = SessionOpenPayload {
            session_type: SessionType::FileTransfer,
        };

        let decoded = SessionOpenPayload::decode(&original.encode()).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn session_opened_payload_round_trip() {
        let original = SessionOpenedPayload {
            status: SessionOpenStatus::Accepted,
        };

        let decoded = SessionOpenedPayload::decode(&original.encode()).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn session_close_payload_round_trip() {
        let original = SessionClosePayload;

        let decoded = SessionClosePayload::decode(&original.encode()).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn session_payload_rejects_wrong_version() {
        assert!(SessionOpenPayload::decode(&[99, 1]).is_err());
        assert!(SessionOpenedPayload::decode(&[99, 1]).is_err());
        assert!(SessionClosePayload::decode(&[99]).is_err());
    }

    #[test]
    fn session_payload_rejects_invalid_length() {
        assert!(SessionOpenPayload::decode(&[1]).is_err());
        assert!(SessionOpenPayload::decode(&[1, 1, 0]).is_err());

        assert!(SessionOpenedPayload::decode(&[1]).is_err());
        assert!(SessionOpenedPayload::decode(&[1, 1, 0]).is_err());

        assert!(SessionClosePayload::decode(&[]).is_err());
        assert!(SessionClosePayload::decode(&[1, 0]).is_err());
    }

    #[test]
    fn session_payload_rejects_unknown_values() {
        assert!(SessionOpenPayload::decode(&[1, 99]).is_err());
        assert!(SessionOpenedPayload::decode(&[1, 99]).is_err());
    }
}

// ============================================================
// Session Resize Payload
// ============================================================

/// Terminal dimensions sent by the Client to the Host.
///
/// Wire format:
/// [version: u8]
/// [rows: u16 BE]
/// [columns: u16 BE]
/// [pixel_width: u16 BE]
/// [pixel_height: u16 BE]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionResizePayload {
    pub rows: u16,
    pub columns: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl SessionResizePayload {
    pub const ENCODED_SIZE: usize = 9;

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        if self.rows == 0 || self.columns == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Terminal rows and columns must be non-zero",
            ));
        }

        let mut payload = Vec::with_capacity(Self::ENCODED_SIZE);

        payload.push(SESSION_PAYLOAD_VERSION);
        payload.extend_from_slice(&self.rows.to_be_bytes());
        payload.extend_from_slice(&self.columns.to_be_bytes());
        payload.extend_from_slice(&self.pixel_width.to_be_bytes());
        payload.extend_from_slice(&self.pixel_height.to_be_bytes());

        Ok(payload)
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.len() != Self::ENCODED_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SessionResize payload length",
            ));
        }

        if payload[0] != SESSION_PAYLOAD_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported SessionResize payload version",
            ));
        }

        let value = Self {
            rows: u16::from_be_bytes([payload[1], payload[2]]),
            columns: u16::from_be_bytes([payload[3], payload[4]]),
            pixel_width: u16::from_be_bytes([payload[5], payload[6]]),
            pixel_height: u16::from_be_bytes([payload[7], payload[8]]),
        };

        if value.rows == 0 || value.columns == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Terminal rows and columns must be non-zero",
            ));
        }

        Ok(value)
    }
}

#[cfg(test)]
mod session_resize_tests {
    use super::*;

    #[test]
    fn resize_payload_round_trip() {
        let original = SessionResizePayload {
            rows: 40,
            columns: 120,
            pixel_width: 1080,
            pixel_height: 1920,
        };

        let encoded = original.encode().unwrap();

        assert_eq!(encoded.len(), SessionResizePayload::ENCODED_SIZE);
        assert_eq!(SessionResizePayload::decode(&encoded).unwrap(), original);
    }

    #[test]
    fn resize_payload_allows_missing_pixel_dimensions() {
        let original = SessionResizePayload {
            rows: 24,
            columns: 80,
            pixel_width: 0,
            pixel_height: 0,
        };

        assert_eq!(
            SessionResizePayload::decode(&original.encode().unwrap()).unwrap(),
            original
        );
    }

    #[test]
    fn resize_payload_rejects_zero_rows_or_columns() {
        let invalid_rows = SessionResizePayload {
            rows: 0,
            columns: 80,
            pixel_width: 0,
            pixel_height: 0,
        };

        let invalid_columns = SessionResizePayload {
            rows: 24,
            columns: 0,
            pixel_width: 0,
            pixel_height: 0,
        };

        assert!(invalid_rows.encode().is_err());
        assert!(invalid_columns.encode().is_err());
    }

    #[test]
    fn resize_payload_rejects_invalid_length() {
        assert!(SessionResizePayload::decode(&[]).is_err());
        assert!(SessionResizePayload::decode(&[1; 8]).is_err());
        assert!(SessionResizePayload::decode(&[1; 10]).is_err());
    }

    #[test]
    fn resize_payload_rejects_wrong_version() {
        let mut payload = SessionResizePayload {
            rows: 24,
            columns: 80,
            pixel_width: 0,
            pixel_height: 0,
        }
        .encode()
        .unwrap();

        payload[0] = 99;

        assert!(SessionResizePayload::decode(&payload).is_err());
    }

    #[test]
    fn resize_payload_rejects_zero_dimensions_on_decode() {
        let mut payload = SessionResizePayload {
            rows: 24,
            columns: 80,
            pixel_width: 0,
            pixel_height: 0,
        }
        .encode()
        .unwrap();

        payload[1] = 0;
        payload[2] = 0;

        assert!(SessionResizePayload::decode(&payload).is_err());
    }
}

// ============================================================
// File Transfer Payloads - Stage 06-A
// ============================================================

pub const FILE_PAYLOAD_VERSION: u8 = 1;
pub const MAX_FILE_PATH_BYTES: usize = 4096;
pub const FILE_SHA256_SIZE: usize = 32;

// ------------------------------------------------------------
// File Begin
// ------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileDirection {
    Upload = 1,
    Download = 2,
}

impl TryFrom<u8> for FileDirection {
    type Error = io::Error;

    fn try_from(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Upload),
            2 => Ok(Self::Download),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown file transfer direction",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBeginPayload {
    pub direction: FileDirection,
    pub file_size: u64,
    pub remote_path: String,
}

impl FileBeginPayload {
    pub fn validate_path(path: &str) -> io::Result<()> {
        if path.is_empty()
            || path.len() > MAX_FILE_PATH_BYTES
            || path.starts_with('/')
            || path.contains('\\')
            || path.contains('\0')
            || path.contains(':')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid remote relative path",
            ));
        }

        for component in path.split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Remote path contains an invalid component",
                ));
            }
        }

        Ok(())
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        Self::validate_path(&self.remote_path)?;

        let path = self.remote_path.as_bytes();
        let path_len = u16::try_from(path.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Remote path is too long"))?;

        let mut payload = Vec::with_capacity(12 + path.len());

        payload.push(FILE_PAYLOAD_VERSION);
        payload.push(self.direction as u8);
        payload.extend_from_slice(&self.file_size.to_be_bytes());
        payload.extend_from_slice(&path_len.to_be_bytes());
        payload.extend_from_slice(path);

        Ok(payload)
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.len() < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FileBegin payload is too short",
            ));
        }

        if payload[0] != FILE_PAYLOAD_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported FileBegin payload version",
            ));
        }

        let direction = FileDirection::try_from(payload[1])?;
        let file_size = u64::from_be_bytes(payload[2..10].try_into().expect("fixed-size slice"));
        let path_len = u16::from_be_bytes([payload[10], payload[11]]) as usize;

        if path_len == 0 || path_len > MAX_FILE_PATH_BYTES || payload.len() != 12 + path_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid FileBegin path length",
            ));
        }

        let remote_path = std::str::from_utf8(&payload[12..])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Remote path is not UTF-8"))?
            .to_owned();

        Self::validate_path(&remote_path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid remote path"))?;

        Ok(Self {
            direction,
            file_size,
            remote_path,
        })
    }
}

// ------------------------------------------------------------
// File Request (download)
// ------------------------------------------------------------

/// Request downloading one file from the Host's configured storage root.
///
/// The path is relative to that root. File metadata is returned separately
/// by the Host using FileBegin with direction Download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRequestPayload {
    pub remote_path: String,
}

impl FileRequestPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        FileBeginPayload::validate_path(&self.remote_path)?;

        let path = self.remote_path.as_bytes();
        let path_len = u16::try_from(path.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Remote path is too long"))?;

        let mut payload = Vec::with_capacity(3 + path.len());
        payload.push(FILE_PAYLOAD_VERSION);
        payload.extend_from_slice(&path_len.to_be_bytes());
        payload.extend_from_slice(path);

        Ok(payload)
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.len() < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FileRequest payload is too short",
            ));
        }

        if payload[0] != FILE_PAYLOAD_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported FileRequest payload version",
            ));
        }

        let path_len = u16::from_be_bytes([payload[1], payload[2]]) as usize;

        if path_len == 0 || path_len > MAX_FILE_PATH_BYTES || payload.len() != 3 + path_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid FileRequest path length",
            ));
        }

        let remote_path = std::str::from_utf8(&payload[3..])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Remote path is not UTF-8"))?
            .to_owned();

        FileBeginPayload::validate_path(&remote_path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid remote path"))?;

        Ok(Self { remote_path })
    }
}

// ------------------------------------------------------------
// File Chunk
// ------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChunkPayload {
    pub chunk_index: u64,
    pub data: Vec<u8>,
}

impl FileChunkPayload {
    pub const HEADER_SIZE: usize = 9;

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        if self.data.is_empty() || self.data.len() > FILE_CHUNK_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid file chunk size",
            ));
        }

        let mut payload = Vec::with_capacity(Self::HEADER_SIZE + self.data.len());

        payload.push(FILE_PAYLOAD_VERSION);
        payload.extend_from_slice(&self.chunk_index.to_be_bytes());
        payload.extend_from_slice(&self.data);

        Ok(payload)
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.len() <= Self::HEADER_SIZE || payload.len() > Self::HEADER_SIZE + FILE_CHUNK_SIZE
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid FileChunk payload size",
            ));
        }

        if payload[0] != FILE_PAYLOAD_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported FileChunk payload version",
            ));
        }

        let chunk_index = u64::from_be_bytes(payload[1..9].try_into().expect("fixed-size slice"));

        Ok(Self {
            chunk_index,
            data: payload[9..].to_vec(),
        })
    }
}

// ------------------------------------------------------------
// File End
// ------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEndPayload {
    pub total_chunks: u64,
    pub total_size: u64,
    pub sha256: [u8; FILE_SHA256_SIZE],
}

impl FileEndPayload {
    pub const ENCODED_SIZE: usize = 49;

    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(Self::ENCODED_SIZE);

        payload.push(FILE_PAYLOAD_VERSION);
        payload.extend_from_slice(&self.total_chunks.to_be_bytes());
        payload.extend_from_slice(&self.total_size.to_be_bytes());
        payload.extend_from_slice(&self.sha256);

        payload
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.len() != Self::ENCODED_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid FileEnd payload length",
            ));
        }

        if payload[0] != FILE_PAYLOAD_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported FileEnd payload version",
            ));
        }

        let mut sha256 = [0u8; FILE_SHA256_SIZE];
        sha256.copy_from_slice(&payload[17..49]);

        Ok(Self {
            total_chunks: u64::from_be_bytes(payload[1..9].try_into().expect("fixed-size slice")),
            total_size: u64::from_be_bytes(payload[9..17].try_into().expect("fixed-size slice")),
            sha256,
        })
    }
}

// ------------------------------------------------------------
// File Response
// ------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileResponseStatus {
    Ready = 1,
    Completed = 2,
    Rejected = 3,
    Failed = 4,
}

impl TryFrom<u8> for FileResponseStatus {
    type Error = io::Error;

    fn try_from(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Ready),
            2 => Ok(Self::Completed),
            3 => Ok(Self::Rejected),
            4 => Ok(Self::Failed),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown file response status",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FileErrorCode {
    None = 0,
    InvalidRequest = 1,
    NotFound = 2,
    PermissionDenied = 3,
    AlreadyExists = 4,
    Io = 5,
    IntegrityMismatch = 6,
    Protocol = 7,
}

impl TryFrom<u16> for FileErrorCode {
    type Error = io::Error;

    fn try_from(value: u16) -> io::Result<Self> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::InvalidRequest),
            2 => Ok(Self::NotFound),
            3 => Ok(Self::PermissionDenied),
            4 => Ok(Self::AlreadyExists),
            5 => Ok(Self::Io),
            6 => Ok(Self::IntegrityMismatch),
            7 => Ok(Self::Protocol),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown file error code",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileResponsePayload {
    pub status: FileResponseStatus,
    pub error_code: FileErrorCode,
}

impl FileResponsePayload {
    pub const ENCODED_SIZE: usize = 4;

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let success = matches!(
            self.status,
            FileResponseStatus::Ready | FileResponseStatus::Completed
        );

        if success != (self.error_code == FileErrorCode::None) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "File response status and error code are inconsistent",
            ));
        }

        let mut payload = Vec::with_capacity(Self::ENCODED_SIZE);

        payload.push(FILE_PAYLOAD_VERSION);
        payload.push(self.status as u8);
        payload.extend_from_slice(&(self.error_code as u16).to_be_bytes());

        Ok(payload)
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.len() != Self::ENCODED_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid FileResponse payload length",
            ));
        }

        if payload[0] != FILE_PAYLOAD_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported FileResponse payload version",
            ));
        }

        let value = Self {
            status: FileResponseStatus::try_from(payload[1])?,
            error_code: FileErrorCode::try_from(u16::from_be_bytes([payload[2], payload[3]]))?,
        };

        let success = matches!(
            value.status,
            FileResponseStatus::Ready | FileResponseStatus::Completed
        );

        if success != (value.error_code == FileErrorCode::None) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "File response status and error code are inconsistent",
            ));
        }

        Ok(value)
    }
}

// ============================================================
// File Transfer Payload Tests
// ============================================================

#[cfg(test)]
mod file_payload_tests {
    use super::*;

    #[test]
    fn file_begin_upload_round_trip() {
        let original = FileBeginPayload {
            direction: FileDirection::Upload,
            file_size: 123456,
            remote_path: "docs/report.txt".to_owned(),
        };

        let encoded = original.encode().unwrap();
        assert_eq!(FileBeginPayload::decode(&encoded).unwrap(), original);
    }

    #[test]
    fn file_begin_download_round_trip() {
        let original = FileBeginPayload {
            direction: FileDirection::Download,
            file_size: 0,
            remote_path: "downloads/archive.bin".to_owned(),
        };

        let encoded = original.encode().unwrap();
        assert_eq!(FileBeginPayload::decode(&encoded).unwrap(), original);
    }

    #[test]
    fn file_begin_rejects_unsafe_paths() {
        for path in [
            "",
            "../secret",
            "docs/../../secret",
            "/etc/passwd",
            "docs//file.txt",
            "./file.txt",
            "docs/./file.txt",
            "C:/secret.txt",
            "docs\\secret.txt",
        ] {
            let value = FileBeginPayload {
                direction: FileDirection::Upload,
                file_size: 1,
                remote_path: path.to_owned(),
            };

            assert!(value.encode().is_err(), "accepted path: {path}");
        }
    }

    #[test]
    fn file_begin_rejects_invalid_wire_data() {
        let valid = FileBeginPayload {
            direction: FileDirection::Upload,
            file_size: 1,
            remote_path: "file.txt".to_owned(),
        }
        .encode()
        .unwrap();

        assert!(FileBeginPayload::decode(&[]).is_err());

        let mut wrong_version = valid.clone();
        wrong_version[0] = 99;
        assert!(FileBeginPayload::decode(&wrong_version).is_err());

        let mut wrong_direction = valid.clone();
        wrong_direction[1] = 99;
        assert!(FileBeginPayload::decode(&wrong_direction).is_err());

        let mut wrong_length = valid;
        wrong_length.push(0);
        assert!(FileBeginPayload::decode(&wrong_length).is_err());
    }

    #[test]
    fn file_chunk_round_trip() {
        let original = FileChunkPayload {
            chunk_index: 42,
            data: vec![0x5A; 4096],
        };

        let encoded = original.encode().unwrap();
        assert_eq!(FileChunkPayload::decode(&encoded).unwrap(), original);
    }

    #[test]
    fn file_chunk_accepts_maximum_chunk() {
        let original = FileChunkPayload {
            chunk_index: 0,
            data: vec![0xA5; FILE_CHUNK_SIZE],
        };

        let encoded = original.encode().unwrap();
        assert_eq!(FileChunkPayload::decode(&encoded).unwrap(), original);
    }

    #[test]
    fn file_chunk_rejects_empty_and_oversized_data() {
        assert!(FileChunkPayload {
            chunk_index: 0,
            data: Vec::new(),
        }
        .encode()
        .is_err());

        assert!(FileChunkPayload {
            chunk_index: 0,
            data: vec![0; FILE_CHUNK_SIZE + 1],
        }
        .encode()
        .is_err());

        assert!(FileChunkPayload::decode(&[FILE_PAYLOAD_VERSION; 9]).is_err());
    }

    #[test]
    fn file_end_round_trip() {
        let original = FileEndPayload {
            total_chunks: 10,
            total_size: 12345,
            sha256: [0xAB; FILE_SHA256_SIZE],
        };

        let encoded = original.encode();
        assert_eq!(encoded.len(), FileEndPayload::ENCODED_SIZE);
        assert_eq!(FileEndPayload::decode(&encoded).unwrap(), original);
    }

    #[test]
    fn file_end_rejects_invalid_length_and_version() {
        assert!(FileEndPayload::decode(&[]).is_err());
        assert!(FileEndPayload::decode(&[0; 48]).is_err());
        assert!(FileEndPayload::decode(&[0; 50]).is_err());

        let mut encoded = FileEndPayload {
            total_chunks: 0,
            total_size: 0,
            sha256: [0; FILE_SHA256_SIZE],
        }
        .encode();

        encoded[0] = 99;
        assert!(FileEndPayload::decode(&encoded).is_err());
    }

    #[test]
    fn file_response_round_trip() {
        for original in [
            FileResponsePayload {
                status: FileResponseStatus::Ready,
                error_code: FileErrorCode::None,
            },
            FileResponsePayload {
                status: FileResponseStatus::Completed,
                error_code: FileErrorCode::None,
            },
            FileResponsePayload {
                status: FileResponseStatus::Rejected,
                error_code: FileErrorCode::PermissionDenied,
            },
            FileResponsePayload {
                status: FileResponseStatus::Failed,
                error_code: FileErrorCode::IntegrityMismatch,
            },
        ] {
            let encoded = original.encode().unwrap();
            assert_eq!(FileResponsePayload::decode(&encoded).unwrap(), original);
        }
    }

    #[test]
    fn file_response_rejects_inconsistent_status() {
        let invalid = FileResponsePayload {
            status: FileResponseStatus::Ready,
            error_code: FileErrorCode::PermissionDenied,
        };

        assert!(invalid.encode().is_err());

        let invalid_wire = [
            FILE_PAYLOAD_VERSION,
            FileResponseStatus::Completed as u8,
            0,
            FileErrorCode::Io as u8,
        ];

        assert!(FileResponsePayload::decode(&invalid_wire).is_err());
    }

    #[test]
    fn file_response_rejects_unknown_values() {
        assert!(FileResponsePayload::decode(&[FILE_PAYLOAD_VERSION, 99, 0, 0,]).is_err());

        assert!(FileResponsePayload::decode(&[
            FILE_PAYLOAD_VERSION,
            FileResponseStatus::Failed as u8,
            0xFF,
            0xFF,
        ])
        .is_err());
    }
}

#[cfg(test)]
mod file_request_payload_tests {
    use super::*;

    #[test]
    fn file_request_round_trip() {
        let request = FileRequestPayload {
            remote_path: "documents/report.txt".to_string(),
        };

        let encoded = request.encode().unwrap();
        let decoded = FileRequestPayload::decode(&encoded).unwrap();

        assert_eq!(decoded, request);
    }

    #[test]
    fn file_request_rejects_unsafe_paths() {
        for path in [
            "",
            "../secret.txt",
            "documents/../secret.txt",
            "/etc/passwd",
            "documents//report.txt",
            "documents/./report.txt",
            "documents\\\\report.txt",
        ] {
            let request = FileRequestPayload {
                remote_path: path.to_string(),
            };

            assert!(
                request.encode().is_err(),
                "Expected path to be rejected: {path:?}"
            );
        }
    }

    #[test]
    fn file_request_rejects_trailing_bytes() {
        let request = FileRequestPayload {
            remote_path: "report.txt".to_string(),
        };

        let mut encoded = request.encode().unwrap();
        encoded.push(0);

        assert!(FileRequestPayload::decode(&encoded).is_err());
    }

    #[test]
    fn file_request_message_kind_is_24() {
        assert_eq!(MessageKind::try_from(24).unwrap(), MessageKind::FileRequest);
    }
}
