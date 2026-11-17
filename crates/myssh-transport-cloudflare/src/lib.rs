use async_trait::async_trait;
use std::io;
use tokio::net::{TcpListener, TcpStream};

use myssh_transport::{BoxedStream, Transport, TransportAcceptor};

/// Official MySSH Cloudflare Transport adapter.
///
/// This adapter connects to local TCP endpoints.
///
/// Client:
/// `endpoint` is the local TCP address exposed by
/// `cloudflared access tcp`.
///
/// Host:
/// `endpoint` is the local TCP address to which
/// the Cloudflare Tunnel forwards incoming connections.
///
/// Cloudflare Tunnel lifecycle and authentication are managed
/// outside this crate.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloudflareTransport;

struct CloudflareAcceptor {
    listener: TcpListener,
}

#[async_trait]
impl TransportAcceptor for CloudflareAcceptor {
    async fn accept(&mut self) -> io::Result<BoxedStream> {
        let (stream, _) = self.listener.accept().await?;

        stream.set_nodelay(true)?;

        Ok(Box::new(stream))
    }
}

#[async_trait]
impl Transport for CloudflareTransport {
    async fn connect(&self, endpoint: &str) -> io::Result<BoxedStream> {
        let stream = TcpStream::connect(endpoint).await?;

        stream.set_nodelay(true)?;

        Ok(Box::new(stream))
    }

    async fn listen(&self, endpoint: &str) -> io::Result<Box<dyn TransportAcceptor>> {
        let listener = TcpListener::bind(endpoint).await?;

        Ok(Box::new(CloudflareAcceptor { listener }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn connects_and_accepts_bidirectional_streams() {
        // Reserve an available local port.
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();

        let address = reservation.local_addr().unwrap().to_string();

        drop(reservation);

        let transport = CloudflareTransport;

        let mut acceptor = transport.listen(&address).await.unwrap();

        let connect_future = transport.connect(&address);
        let accept_future = acceptor.accept();

        let (client_result, server_result) = tokio::join!(connect_future, accept_future);

        let mut client = client_result.unwrap();
        let mut server = server_result.unwrap();

        // Client -> Host
        client.write_all(b"MySSH Client").await.unwrap();

        let mut buffer = [0u8; 12];
        server.read_exact(&mut buffer).await.unwrap();

        assert_eq!(&buffer, b"MySSH Client");

        // Host -> Client
        server.write_all(b"MySSH Host!").await.unwrap();

        let mut response = [0u8; 11];
        client.read_exact(&mut response).await.unwrap();

        assert_eq!(&response, b"MySSH Host!");
    }
}
