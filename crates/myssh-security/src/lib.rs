use std::io;
use std::sync::Arc;

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    ClientConfig, RootCertStore, ServerConfig,
};

use tokio_rustls::{TlsAcceptor, TlsConnector};

use myssh_transport::BoxedStream;

/// A bidirectional TLS-protected stream.
///
/// TLS is applied above the transport layer.
/// The underlying transport does not need to understand TLS.
pub type SecureStream = BoxedStream;

/// Build a TLS server configuration.
///
/// The server presents its certificate to the client.
/// Client certificate authentication will be added separately.
pub fn build_server_config(
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;

    Ok(Arc::new(config))
}

/// Build a TLS client configuration.
///
/// Only certificates in this root store are trusted.
/// Do not use an empty or permissive verifier in production.
pub fn build_client_config(
    trusted_certificates: Vec<CertificateDer<'static>>,
) -> Result<Arc<ClientConfig>, rustls::Error> {
    let mut root_store = RootCertStore::empty();

    for certificate in trusted_certificates {
        root_store.add(certificate)?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// Perform the server-side TLS handshake.
pub async fn server_handshake(
    stream: BoxedStream,
    config: Arc<ServerConfig>,
) -> io::Result<SecureStream> {
    let acceptor = TlsAcceptor::from(config);

    let tls_stream = acceptor.accept(stream).await.map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("TLS server handshake failed: {error}"),
        )
    })?;

    Ok(Box::new(tls_stream))
}

/// Perform the client-side TLS handshake.
///
/// `server_name` must match the identity in the server certificate.
/// For DNS names, use the certificate's DNS SAN.
/// For IP connections, supply a rustls ServerName containing an IP address.
pub async fn client_handshake(
    stream: BoxedStream,
    server_name: ServerName<'static>,
    config: Arc<ClientConfig>,
) -> io::Result<SecureStream> {
    let connector = TlsConnector::from(config);

    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("TLS client handshake failed: {error}"),
            )
        })?;

    Ok(Box::new(tls_stream))
}

// ============================================================
// TLS integration tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    use rcgen::{CertificateParams, KeyPair};

    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    fn generate_test_certificate() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();

        let key_pair = KeyPair::generate().unwrap();

        let certificate = params.self_signed(&key_pair).unwrap();

        let certificate_der = certificate.der().clone();

        let private_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        (certificate_der, private_key_der)
    }

    fn create_server_config() -> (Arc<ServerConfig>, CertificateDer<'static>) {
        let (certificate, private_key) = generate_test_certificate();

        let config = build_server_config(vec![certificate.clone()], private_key).unwrap();

        (config, certificate)
    }

    #[tokio::test]
    async fn accepts_trusted_certificate() {
        let (server_config, certificate) = create_server_config();

        let client_config = build_client_config(vec![certificate]).unwrap();

        let server_name = ServerName::try_from("localhost".to_string()).unwrap();

        let (client_io, server_io) = duplex(65536);

        let (client_result, server_result) = tokio::join!(
            client_handshake(Box::new(client_io), server_name, client_config,),
            server_handshake(Box::new(server_io), server_config,),
        );

        let mut client_stream = client_result.unwrap();
        let mut server_stream = server_result.unwrap();

        client_stream.write_all(b"MySSH TLS").await.unwrap();

        let mut received = [0u8; 9];

        server_stream.read_exact(&mut received).await.unwrap();

        assert_eq!(&received, b"MySSH TLS");
    }

    #[tokio::test]
    async fn rejects_untrusted_certificate() {
        let (server_config, _) = create_server_config();

        let client_config = build_client_config(Vec::new()).unwrap();

        let server_name = ServerName::try_from("localhost".to_string()).unwrap();

        let (client_io, server_io) = duplex(65536);

        let (client_result, server_result) = tokio::join!(
            client_handshake(Box::new(client_io), server_name, client_config,),
            server_handshake(Box::new(server_io), server_config,),
        );

        assert!(client_result.is_err());
        assert!(server_result.is_err());
    }

    #[tokio::test]
    async fn rejects_wrong_server_name() {
        let (server_config, certificate) = create_server_config();

        let client_config = build_client_config(vec![certificate]).unwrap();

        let wrong_server_name = ServerName::try_from("wrong.example".to_string()).unwrap();

        let (client_io, server_io) = duplex(65536);

        let (client_result, server_result) = tokio::join!(
            client_handshake(Box::new(client_io), wrong_server_name, client_config,),
            server_handshake(Box::new(server_io), server_config,),
        );

        assert!(client_result.is_err());
        assert!(server_result.is_err());
    }
}
