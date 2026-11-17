use async_trait::async_trait;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

/// A bidirectional asynchronous byte stream.
///
/// The stream carries opaque bytes. MySSH protocol framing and TLS
/// are handled by higher layers, not by the transport implementation.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A boxed bidirectional stream shared by all transport adapters.
pub type BoxedStream = Box<dyn AsyncStream>;

/// A server-side object that accepts incoming streams.
#[async_trait]
pub trait TransportAcceptor: Send {
    async fn accept(&mut self) -> io::Result<BoxedStream>;
}

/// Transport abstraction.
///
/// Implementations may use TCP, Cloudflare Tunnel, or another
/// user-provided network path.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Establish an outgoing connection.
    ///
    /// `endpoint` is supplied dynamically by the application.
    async fn connect(&self, endpoint: &str) -> io::Result<BoxedStream>;

    /// Start listening for incoming connections.
    ///
    /// Returns an acceptor that can produce incoming streams.
    async fn listen(&self, endpoint: &str) -> io::Result<Box<dyn TransportAcceptor>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn boxed_stream_supports_bidirectional_io() {
        let (left, mut right) = duplex(64);

        let mut stream: BoxedStream = Box::new(left);

        stream.write_all(b"MySSH").await.unwrap();

        let mut buffer = [0u8; 5];

        right.read_exact(&mut buffer).await.unwrap();

        assert_eq!(&buffer, b"MySSH");

        right.write_all(b"World").await.unwrap();

        let mut response = [0u8; 5];

        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"World");
    }
}
