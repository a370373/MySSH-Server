use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::ServerConfig;

use myssh_auth::{AuthServer, AuthenticatedIdentity};
use myssh_protocol::{
    read_frame, write_frame, AuthProofPayload, AuthRequestPayload, AuthResponsePayload, AuthStatus,
    Frame, MessageKind,
};
use myssh_security::{server_handshake, SecureStream};
use myssh_transport::BoxedStream;

use tokio::time::timeout;

use crate::auth_bridge::{
    issue_challenge as bridge_issue_challenge, verify_proof as bridge_verify_proof,
};

/// A TLS connection that has completed MySSH Ed25519 authentication.
pub struct AuthenticatedConnection {
    pub stream: SecureStream,
    pub identity: AuthenticatedIdentity,
}

/// Cloneable shared authentication state for concurrent connections.
#[derive(Clone)]
pub struct SharedAuthServer {
    inner: Arc<Mutex<AuthServer>>,
}

impl SharedAuthServer {
    pub fn new(auth_server: AuthServer) -> Self {
        Self {
            inner: Arc::new(Mutex::new(auth_server)),
        }
    }
}

trait AuthBackend: Send {
    fn issue_challenge(
        &mut self,
        request: &AuthRequestPayload,
    ) -> io::Result<myssh_protocol::AuthChallengePayload>;

    fn verify_proof(&mut self, proof: &AuthProofPayload) -> io::Result<AuthenticatedIdentity>;
}

impl AuthBackend for &mut AuthServer {
    fn issue_challenge(
        &mut self,
        request: &AuthRequestPayload,
    ) -> io::Result<myssh_protocol::AuthChallengePayload> {
        bridge_issue_challenge(*self, request)
    }

    fn verify_proof(&mut self, proof: &AuthProofPayload) -> io::Result<AuthenticatedIdentity> {
        bridge_verify_proof(*self, proof)
    }
}

impl AuthBackend for SharedAuthServer {
    fn issue_challenge(
        &mut self,
        request: &AuthRequestPayload,
    ) -> io::Result<myssh_protocol::AuthChallengePayload> {
        let mut guard = self.inner.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Authentication state lock poisoned")
        })?;

        bridge_issue_challenge(&mut guard, request)
    }

    fn verify_proof(&mut self, proof: &AuthProofPayload) -> io::Result<AuthenticatedIdentity> {
        let mut guard = self.inner.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Authentication state lock poisoned")
        })?;

        bridge_verify_proof(&mut guard, proof)
    }
}

async fn with_timeout<T, F>(duration: Duration, future: F) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    timeout(duration, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MySSH operation timed out"))?
}

async fn send_auth_response(
    stream: &mut SecureStream,
    request_id: u64,
    status: AuthStatus,
    duration: Duration,
) -> io::Result<()> {
    let payload = AuthResponsePayload { status }.encode();

    let frame = Frame::new(MessageKind::AuthResponse, 0, request_id, payload)?;

    with_timeout(duration, write_frame(stream, &frame)).await
}

fn protocol_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Authenticate one incoming transport stream.
///
/// The caller supplies the shared TLS server configuration and the
/// authentication server. No transport-specific implementation is used here.
///
/// On success, the returned stream is already TLS-protected and authenticated.
/// The caller may then pass it to the session or file-transfer layer.
pub async fn authenticate_connection(
    transport_stream: BoxedStream,
    tls_config: Arc<ServerConfig>,
    auth_server: &mut AuthServer,
    operation_timeout: Duration,
) -> io::Result<AuthenticatedConnection> {
    authenticate_connection_inner(transport_stream, tls_config, auth_server, operation_timeout)
        .await
}

/// Authenticate using cloneable shared authentication state.
pub async fn authenticate_connection_shared(
    transport_stream: BoxedStream,
    tls_config: Arc<ServerConfig>,
    auth_server: SharedAuthServer,
    operation_timeout: Duration,
) -> io::Result<AuthenticatedConnection> {
    authenticate_connection_inner(transport_stream, tls_config, auth_server, operation_timeout)
        .await
}

async fn authenticate_connection_inner<A: AuthBackend>(
    transport_stream: BoxedStream,
    tls_config: Arc<ServerConfig>,
    mut auth_backend: A,
    operation_timeout: Duration,
) -> io::Result<AuthenticatedConnection> {
    if operation_timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Authentication timeout must be greater than zero",
        ));
    }

    // 1. TLS handshake.
    let mut secure_stream = with_timeout(
        operation_timeout,
        server_handshake(transport_stream, tls_config),
    )
    .await?;

    // 2. Receive AuthRequest.
    let request_frame = with_timeout(operation_timeout, read_frame(&mut secure_stream)).await?;

    if request_frame.header.kind != MessageKind::AuthRequest {
        let _ = send_auth_response(
            &mut secure_stream,
            request_frame.header.request_id,
            AuthStatus::ProtocolError,
            operation_timeout,
        )
        .await;

        return Err(protocol_error("Expected AuthRequest"));
    }

    if request_frame.header.session_id != 0 {
        let _ = send_auth_response(
            &mut secure_stream,
            request_frame.header.request_id,
            AuthStatus::ProtocolError,
            operation_timeout,
        )
        .await;

        return Err(protocol_error("Authentication frame must use session_id 0"));
    }

    let request = match AuthRequestPayload::decode(&request_frame.payload) {
        Ok(request) => request,
        Err(error) => {
            let _ = send_auth_response(
                &mut secure_stream,
                request_frame.header.request_id,
                AuthStatus::ProtocolError,
                operation_timeout,
            )
            .await;

            return Err(error);
        }
    };

    // 3. Create and send AuthChallenge.
    let challenge = match auth_backend.issue_challenge(&request) {
        Ok(challenge) => challenge,
        Err(_) => {
            send_auth_response(
                &mut secure_stream,
                request_frame.header.request_id,
                AuthStatus::Denied,
                operation_timeout,
            )
            .await?;

            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Client authentication denied",
            ));
        }
    };

    let challenge_payload = challenge.encode()?;

    let challenge_frame = Frame::new(
        MessageKind::AuthChallenge,
        0,
        request_frame.header.request_id,
        challenge_payload,
    )?;

    with_timeout(
        operation_timeout,
        write_frame(&mut secure_stream, &challenge_frame),
    )
    .await?;

    // 4. Receive AuthProof.
    let proof_frame = with_timeout(operation_timeout, read_frame(&mut secure_stream)).await?;

    if proof_frame.header.kind != MessageKind::AuthProof
        || proof_frame.header.session_id != 0
        || proof_frame.header.request_id != request_frame.header.request_id
    {
        let _ = send_auth_response(
            &mut secure_stream,
            request_frame.header.request_id,
            AuthStatus::ProtocolError,
            operation_timeout,
        )
        .await;

        return Err(protocol_error("Unexpected authentication proof frame"));
    }

    let proof_payload = match AuthProofPayload::decode(&proof_frame.payload) {
        Ok(proof) => proof,
        Err(error) => {
            let _ = send_auth_response(
                &mut secure_stream,
                request_frame.header.request_id,
                AuthStatus::ProtocolError,
                operation_timeout,
            )
            .await;

            return Err(error);
        }
    };

    // 5. Verify Ed25519 proof.
    let identity = match auth_backend.verify_proof(&proof_payload) {
        Ok(identity) => identity,
        Err(_) => {
            send_auth_response(
                &mut secure_stream,
                request_frame.header.request_id,
                AuthStatus::Denied,
                operation_timeout,
            )
            .await?;

            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Client authentication failed",
            ));
        }
    };

    // 6. Authentication succeeded.
    send_auth_response(
        &mut secure_stream,
        request_frame.header.request_id,
        AuthStatus::Success,
        operation_timeout,
    )
    .await?;

    Ok(AuthenticatedConnection {
        stream: secure_stream,
        identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use myssh_auth::{AuthServer, Challenge, ClientKeyPair, TrustStore};
    use myssh_protocol::{
        read_frame, write_frame, AuthChallengePayload, AuthRequestPayload, AuthStatus, Frame,
        MessageKind,
    };
    use myssh_security::{build_client_config, build_server_config, client_handshake};

    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

    use tokio::io::duplex;

    fn create_tls_configs() -> (Arc<ServerConfig>, Arc<rustls::ClientConfig>) {
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key_pair).unwrap();

        let certificate_der: CertificateDer<'static> = certificate.der().clone();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        let server_config =
            build_server_config(vec![certificate_der.clone()], private_key).unwrap();

        let client_config = build_client_config(vec![certificate_der]).unwrap();

        (server_config, client_config)
    }

    fn create_auth_server() -> (AuthServer, ClientKeyPair) {
        let client_key = ClientKeyPair::generate();

        let mut trust_store = TrustStore::new();
        trust_store
            .add("test-user", client_key.public_key_bytes())
            .unwrap();

        let auth_server = AuthServer::new(trust_store, Duration::from_secs(30));

        (auth_server, client_key)
    }

    fn sign_challenge(
        client_key: &ClientKeyPair,
        payload: &AuthChallengePayload,
    ) -> AuthProofPayload {
        let challenge = Challenge {
            challenge_id: payload.challenge_id,
            nonce: payload.nonce,
            username: payload.username.clone(),
            key_id: payload.key_id.clone(),
            protocol_version: payload.protocol_version,
        };

        let proof = client_key.sign_challenge(&challenge).unwrap();

        AuthProofPayload {
            challenge_id: proof.challenge_id,
            signature: proof.signature,
        }
    }

    #[tokio::test]
    async fn completes_tls_and_ed25519_authentication() {
        let (server_config, client_config) = create_tls_configs();
        let (mut auth_server, client_key) = create_auth_server();

        let (client_io, server_io) = duplex(65536);

        let server_task = async {
            authenticate_connection(
                Box::new(server_io),
                server_config,
                &mut auth_server,
                Duration::from_secs(5),
            )
            .await
        };

        let client_task = async {
            let server_name = ServerName::try_from("localhost".to_string()).unwrap();

            let mut stream = client_handshake(Box::new(client_io), server_name, client_config)
                .await
                .unwrap();

            let request = AuthRequestPayload {
                username: "test-user".to_string(),
                key_id: client_key.key_id(),
            };

            let request_frame =
                Frame::new(MessageKind::AuthRequest, 0, 1, request.encode().unwrap()).unwrap();

            write_frame(&mut stream, &request_frame).await.unwrap();

            let challenge_frame = read_frame(&mut stream).await.unwrap();
            assert_eq!(challenge_frame.header.kind, MessageKind::AuthChallenge);

            let challenge = AuthChallengePayload::decode(&challenge_frame.payload).unwrap();

            let proof = sign_challenge(&client_key, &challenge);

            let proof_frame = Frame::new(MessageKind::AuthProof, 0, 1, proof.encode()).unwrap();

            write_frame(&mut stream, &proof_frame).await.unwrap();

            let response_frame = read_frame(&mut stream).await.unwrap();
            assert_eq!(response_frame.header.kind, MessageKind::AuthResponse);

            let response = AuthResponsePayload::decode(&response_frame.payload).unwrap();

            assert_eq!(response.status, AuthStatus::Success);
        };

        let (server_result, ()) = tokio::join!(server_task, client_task);

        let authenticated = server_result.unwrap();

        assert_eq!(authenticated.identity.username, "test-user");
        assert_eq!(authenticated.identity.key_id, client_key.key_id());
    }

    #[tokio::test]
    async fn rejects_untrusted_client() {
        let (server_config, client_config) = create_tls_configs();

        let mut auth_server = AuthServer::new(TrustStore::new(), Duration::from_secs(30));

        let client_key = ClientKeyPair::generate();
        let (client_io, server_io) = duplex(65536);

        let server_task = async {
            authenticate_connection(
                Box::new(server_io),
                server_config,
                &mut auth_server,
                Duration::from_secs(5),
            )
            .await
        };

        let client_task = async {
            let server_name = ServerName::try_from("localhost".to_string()).unwrap();

            let mut stream = client_handshake(Box::new(client_io), server_name, client_config)
                .await
                .unwrap();

            let request = AuthRequestPayload {
                username: "unknown-user".to_string(),
                key_id: client_key.key_id(),
            };

            let frame =
                Frame::new(MessageKind::AuthRequest, 0, 7, request.encode().unwrap()).unwrap();

            write_frame(&mut stream, &frame).await.unwrap();

            let response_frame = read_frame(&mut stream).await.unwrap();
            let response = AuthResponsePayload::decode(&response_frame.payload).unwrap();

            assert_eq!(response.status, AuthStatus::Denied);
        };

        let (server_result, ()) = tokio::join!(server_task, client_task);

        assert!(server_result.is_err());
    }

    #[tokio::test]
    async fn rejects_zero_timeout() {
        let (server_config, _) = create_tls_configs();
        let (mut auth_server, _) = create_auth_server();
        let (client_io, server_io) = duplex(64);

        let result = authenticate_connection(
            Box::new(server_io),
            server_config,
            &mut auth_server,
            Duration::ZERO,
        )
        .await;

        drop(client_io);

        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidInput);
    }
}
