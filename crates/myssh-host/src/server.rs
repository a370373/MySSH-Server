use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use myssh_auth::AuthServer;
use myssh_transport::Transport;
use rustls::ServerConfig;

use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::auth_connection::{authenticate_connection_shared, SharedAuthServer};
use crate::file_transfer::HostFileStore;
use crate::terminal_bridge::run_terminal_connection_with_file_store;

/// Maximum number of active connection handlers.
pub const MAX_ACTIVE_CONNECTIONS: usize = 128;

/// Run the generic MySSH Host listener indefinitely.
///
/// This convenience function preserves the original API.
/// Applications that need controlled shutdown should use
/// `run_server_with_shutdown`.
pub async fn run_server(
    transport: &dyn Transport,
    endpoint: &str,
    tls_config: Arc<ServerConfig>,
    auth_server: AuthServer,
    file_store: HostFileStore,
    operation_timeout: Duration,
) -> io::Result<()> {
    run_server_with_shutdown(
        transport,
        endpoint,
        tls_config,
        auth_server,
        file_store,
        operation_timeout,
        Duration::from_secs(5),
        std::future::pending::<()>(),
    )
    .await
}

/// Run the generic MySSH Host listener with controlled shutdown.
///
/// When `shutdown` completes:
/// 1. Stop accepting new connections.
/// 2. Allow active connection handlers to finish.
/// 3. Abort remaining handlers after the grace period.
/// 4. Drain all remaining task results.
///
/// This function depends only on the generic Transport interface.
pub async fn run_server_with_shutdown<F>(
    transport: &dyn Transport,
    endpoint: &str,
    tls_config: Arc<ServerConfig>,
    auth_server: AuthServer,
    file_store: HostFileStore,
    operation_timeout: Duration,
    graceful_shutdown_timeout: Duration,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send,
{
    if endpoint.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Transport endpoint must not be empty",
        ));
    }

    if operation_timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Operation timeout must be greater than zero",
        ));
    }

    let mut acceptor = transport.listen(endpoint).await?;
    let shared_auth = SharedAuthServer::new(auth_server);
    let mut connections = JoinSet::new();

    tokio::pin!(shutdown);

    let shutting_down = loop {
        tokio::select! {
            _ = &mut shutdown => {
                break true;
            }

            accepted = acceptor.accept() => {
                let stream = accepted?;

                // Reject excess connections without creating more tasks.
                if connections.len() >= MAX_ACTIVE_CONNECTIONS {
                    drop(stream);
                    continue;
                }

                let tls = Arc::clone(&tls_config);
                let auth = shared_auth.clone();
                let store = file_store.clone();

                connections.spawn(async move {
                    let result = async {
                        let authenticated = authenticate_connection_shared(
                            stream,
                            tls,
                            auth,
                            operation_timeout,
                        )
                        .await?;

                        run_terminal_connection_with_file_store(
                            authenticated,
                            store,
                        )
                        .await
                    }
                    .await;

                    if let Err(error) = result {
                        eprintln!("MySSH connection ended: {error}");
                    }
                });
            }

            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = joined {
                    eprintln!("MySSH connection task failed: {error}");
                }
            }
        }
    };

    if !shutting_down {
        return Ok(());
    }

    // Dropping the acceptor stops accepting new connections.
    drop(acceptor);

    eprintln!("MySSH Host: graceful shutdown started.");

    // Give active sessions time to finish naturally.
    let drain_result = timeout(graceful_shutdown_timeout, async {
        while let Some(joined) = connections.join_next().await {
            if let Err(error) = joined {
                eprintln!("MySSH connection task failed during shutdown: {error}");
            }
        }
    })
    .await;

    if drain_result.is_err() {
        eprintln!("MySSH Host: shutdown grace period expired; aborting remaining connections.");

        connections.abort_all();

        // Reap all aborted tasks before returning.
        while let Some(joined) = connections.join_next().await {
            if let Err(error) = joined {
                if !error.is_cancelled() {
                    eprintln!("MySSH connection task failed during forced shutdown: {error}");
                }
            }
        }
    }

    eprintln!("MySSH Host: shutdown complete.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use async_trait::async_trait;
    use myssh_auth::TrustStore;
    use myssh_transport::{BoxedStream, TransportAcceptor};
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{duplex, AsyncReadExt};
    use tokio::sync::{mpsc, oneshot, Notify};

    use crate::file_transfer::HostFileStore;
    use myssh_security::build_server_config;

    struct FakeAcceptor {
        receiver: mpsc::Receiver<BoxedStream>,
        accepted: Arc<Notify>,
    }

    #[async_trait]
    impl TransportAcceptor for FakeAcceptor {
        async fn accept(&mut self) -> io::Result<BoxedStream> {
            let stream = self.receiver.recv().await.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Fake transport channel closed",
                )
            })?;

            self.accepted.notify_one();
            Ok(stream)
        }
    }

    struct FakeTransport {
        sender: Mutex<Option<mpsc::Sender<BoxedStream>>>,
        accepted: Arc<Notify>,
        listen_ready: Arc<Notify>,
        listen_calls: AtomicUsize,
    }

    impl FakeTransport {
        fn new() -> Self {
            Self {
                sender: Mutex::new(None),
                accepted: Arc::new(Notify::new()),
                listen_ready: Arc::new(Notify::new()),
                listen_calls: AtomicUsize::new(0),
            }
        }

        async fn send_stream(&self, stream: BoxedStream) {
            let sender = self.sender.lock().unwrap().as_ref().unwrap().clone();

            sender.send(stream).await.unwrap();
        }
    }

    #[async_trait]
    impl Transport for FakeTransport {
        async fn connect(&self, _endpoint: &str) -> io::Result<BoxedStream> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Fake transport does not implement outgoing connections",
            ))
        }

        async fn listen(&self, _endpoint: &str) -> io::Result<Box<dyn TransportAcceptor>> {
            self.listen_calls.fetch_add(1, Ordering::SeqCst);

            let (sender, receiver) = mpsc::channel(8);
            *self.sender.lock().unwrap() = Some(sender);
            self.listen_ready.notify_one();

            Ok(Box::new(FakeAcceptor {
                receiver,
                accepted: Arc::clone(&self.accepted),
            }))
        }
    }

    fn test_tls_config() -> Arc<ServerConfig> {
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key_pair).unwrap();

        let certificate_der: CertificateDer<'static> = certificate.der().clone();

        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        build_server_config(vec![certificate_der], private_key).unwrap()
    }

    fn test_auth_server() -> AuthServer {
        AuthServer::new(TrustStore::new(), Duration::from_secs(60))
    }

    fn test_file_store() -> (HostFileStore, PathBuf) {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);

        let path = std::env::temp_dir().join(format!(
            "myssh-server-test-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed),
        ));

        std::fs::create_dir_all(&path).unwrap();

        let store = HostFileStore::new(&path, 1024 * 1024).unwrap();
        (store, path)
    }

    #[tokio::test]
    async fn shutdown_returns_when_no_connections_are_active() {
        let transport = FakeTransport::new();
        let (store, path) = test_file_store();

        let result = run_server_with_shutdown(
            &transport,
            "fake://test",
            test_tls_config(),
            test_auth_server(),
            store,
            Duration::from_secs(5),
            Duration::from_secs(1),
            async {},
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(transport.listen_calls.load(Ordering::SeqCst), 1,);

        std::fs::remove_dir_all(path).unwrap();
    }

    #[tokio::test]
    async fn shutdown_aborts_connection_after_grace_period() {
        let transport = Arc::new(FakeTransport::new());
        let (store, path) = test_file_store();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server_transport = Arc::clone(&transport);
        let listener_ready = Arc::clone(&transport.listen_ready);

        let server_task = tokio::spawn(async move {
            run_server_with_shutdown(
                server_transport.as_ref(),
                "fake://test",
                test_tls_config(),
                test_auth_server(),
                store,
                Duration::from_secs(30),
                Duration::from_millis(50),
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });

        // Wait until listen() has created the channel.

        listener_ready.notified().await;

        let (server_stream, mut client_stream) = duplex(4096);

        transport.send_stream(Box::new(server_stream)).await;

        // Wait until the listener has accepted the stream.
        transport.accepted.notified().await;

        // Allow the connection handler to enter the TLS handshake.
        tokio::task::yield_now().await;

        // Trigger shutdown while TLS handshake is still waiting.
        shutdown_tx.send(()).unwrap();

        let result = server_task.await.unwrap();
        assert!(result.is_ok());

        // The server-side stream must be dropped after forced cancellation.
        let mut buffer = [0u8; 1];
        let bytes_read = client_stream.read(&mut buffer).await.unwrap();

        assert_eq!(bytes_read, 0);

        std::fs::remove_dir_all(path).unwrap();
    }
}
