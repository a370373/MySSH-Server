use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use myssh_transport::Transport;
use rustls::{pki_types::ServerName, ClientConfig};
use tokio::time::timeout;

use crate::auth::{authenticate_with_key_file, AuthenticatedClient};

/// Establish a connection through any MySSH Transport implementation,
/// then complete TLS and Ed25519 authentication.
pub async fn connect_and_authenticate(
    transport: &dyn Transport,
    endpoint: &str,
    server_name: ServerName<'static>,
    tls_config: Arc<ClientConfig>,
    username: &str,
    key_path: impl AsRef<Path>,
    operation_timeout: Duration,
) -> io::Result<AuthenticatedClient> {
    if operation_timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Connection timeout must be greater than zero",
        ));
    }

    if endpoint.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Transport endpoint must not be empty",
        ));
    }

    // 1. Establish the underlying transport connection.
    let transport_stream = timeout(operation_timeout, transport.connect(endpoint))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "MySSH transport connection timed out",
            )
        })??;

    // 2. Perform TLS and Ed25519 authentication.
    authenticate_with_key_file(
        transport_stream,
        server_name,
        tls_config,
        username,
        key_path,
        operation_timeout,
    )
    .await
}

#[cfg(test)]
mod test_support {
    use std::sync::Arc;

    pub fn empty_client_config() -> Arc<rustls::ClientConfig> {
        myssh_security::build_client_config(Vec::new()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use myssh_transport::{BoxedStream, TransportAcceptor};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct TestTransport {
        connect_called: Arc<AtomicBool>,
    }

    #[async_trait]
    impl Transport for TestTransport {
        async fn connect(&self, _endpoint: &str) -> io::Result<BoxedStream> {
            self.connect_called.store(true, Ordering::SeqCst);

            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "test connection refused",
            ))
        }

        async fn listen(&self, _endpoint: &str) -> io::Result<Box<dyn TransportAcceptor>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "listen is not used in this test",
            ))
        }
    }

    #[tokio::test]
    async fn rejects_zero_timeout_before_connecting() {
        let called = Arc::new(AtomicBool::new(false));
        let transport = TestTransport {
            connect_called: called.clone(),
        };

        let tls_config = super::test_support::empty_client_config();

        let result = connect_and_authenticate(
            &transport,
            "test-endpoint",
            ServerName::try_from("localhost").unwrap(),
            tls_config,
            "test-user",
            "/nonexistent/myssh-test-key",
            Duration::ZERO,
        )
        .await;

        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("expected connection validation error"),
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn rejects_empty_endpoint_before_connecting() {
        let called = Arc::new(AtomicBool::new(false));
        let transport = TestTransport {
            connect_called: called.clone(),
        };

        let tls_config = super::test_support::empty_client_config();

        let result = connect_and_authenticate(
            &transport,
            "",
            ServerName::try_from("localhost").unwrap(),
            tls_config,
            "test-user",
            "/nonexistent/myssh-test-key",
            Duration::from_secs(5),
        )
        .await;

        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("expected connection validation error"),
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!called.load(Ordering::SeqCst));
    }
}
