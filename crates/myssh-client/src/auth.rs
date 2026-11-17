use std::io;
use std::sync::Arc;
use std::time::Duration;

use myssh_auth::{Challenge, ClientKeyPair};
use myssh_protocol::{
    read_frame, write_frame, AuthChallengePayload, AuthProofPayload, AuthRequestPayload,
    AuthResponsePayload, AuthStatus, Frame, MessageKind,
};
use myssh_security::{client_handshake, SecureStream};
use myssh_transport::BoxedStream;

use rustls::{pki_types::ServerName, ClientConfig};
use tokio::time::timeout;

const AUTH_REQUEST_ID: u64 = 1;

/// A Client connection that completed TLS and Ed25519 authentication.
pub struct AuthenticatedClient {
    pub stream: SecureStream,
    pub username: String,
    pub key_id: String,
}

fn protocol_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

async fn with_timeout<T, F>(duration: Duration, future: F) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    timeout(duration, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MySSH operation timed out"))?
}

fn validate_auth_frame(
    frame: &Frame,
    expected_kind: MessageKind,
    expected_request_id: u64,
) -> io::Result<()> {
    if frame.header.kind != expected_kind {
        return Err(protocol_error("Unexpected authentication message type"));
    }

    if frame.header.session_id != 0 {
        return Err(protocol_error("Authentication frame must use session_id 0"));
    }

    if frame.header.request_id != expected_request_id {
        return Err(protocol_error("Authentication request_id does not match"));
    }

    Ok(())
}

fn status_error(status: AuthStatus) -> io::Error {
    match status {
        AuthStatus::Denied => io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Host denied Client authentication",
        ),
        AuthStatus::Unsupported => io::Error::new(
            io::ErrorKind::Unsupported,
            "Host does not support this authentication protocol",
        ),
        AuthStatus::ProtocolError => {
            protocol_error("Host reported an authentication protocol error")
        }
        AuthStatus::Success => protocol_error("Unexpected authentication success response"),
    }
}

/// Complete the Client-side TLS and Ed25519 authentication flow.
///
/// The supplied stream must come from a MySSH Transport implementation.
/// The TLS configuration must explicitly trust the expected Host certificate.
pub async fn authenticate(
    transport_stream: BoxedStream,
    server_name: ServerName<'static>,
    tls_config: Arc<ClientConfig>,
    username: &str,
    key_pair: &ClientKeyPair,
    operation_timeout: Duration,
) -> io::Result<AuthenticatedClient> {
    if operation_timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Authentication timeout must be greater than zero",
        ));
    }

    if username.is_empty() || username.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid MySSH username",
        ));
    }

    let key_id = key_pair.key_id();

    // 1. Establish TLS and verify the Host certificate and server name.
    let mut secure_stream = with_timeout(
        operation_timeout,
        client_handshake(transport_stream, server_name, tls_config),
    )
    .await?;

    // 2. Send AuthRequest.
    let request = AuthRequestPayload {
        username: username.to_string(),
        key_id: key_id.clone(),
    };

    let request_frame = Frame::new(
        MessageKind::AuthRequest,
        0,
        AUTH_REQUEST_ID,
        request.encode()?,
    )?;

    with_timeout(
        operation_timeout,
        write_frame(&mut secure_stream, &request_frame),
    )
    .await?;

    // 3. Receive either an AuthChallenge or an early rejection.
    let challenge_frame = with_timeout(operation_timeout, read_frame(&mut secure_stream)).await?;

    if challenge_frame.header.kind == MessageKind::AuthResponse {
        validate_auth_frame(&challenge_frame, MessageKind::AuthResponse, AUTH_REQUEST_ID)?;

        let response = AuthResponsePayload::decode(&challenge_frame.payload)?;

        return Err(status_error(response.status));
    }

    validate_auth_frame(
        &challenge_frame,
        MessageKind::AuthChallenge,
        AUTH_REQUEST_ID,
    )?;

    let challenge_payload = AuthChallengePayload::decode(&challenge_frame.payload)?;

    // Do not sign a challenge for another identity.
    if challenge_payload.username != username {
        return Err(protocol_error(
            "Host challenge username does not match the requested username",
        ));
    }

    if challenge_payload.key_id != key_id {
        return Err(protocol_error(
            "Host challenge key_id does not match the Client key",
        ));
    }

    // 4. Reconstruct the Auth crate Challenge and sign it.
    let challenge = Challenge {
        challenge_id: challenge_payload.challenge_id,
        nonce: challenge_payload.nonce,
        username: challenge_payload.username,
        key_id: challenge_payload.key_id,
        protocol_version: challenge_payload.protocol_version,
    };

    let proof = key_pair.sign_challenge(&challenge).map_err(|error| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Could not sign Host challenge: {error}"),
        )
    })?;

    // 5. Send AuthProof.
    let proof_payload = AuthProofPayload {
        challenge_id: proof.challenge_id,
        signature: proof.signature,
    };

    let proof_frame = Frame::new(
        MessageKind::AuthProof,
        0,
        AUTH_REQUEST_ID,
        proof_payload.encode(),
    )?;

    with_timeout(
        operation_timeout,
        write_frame(&mut secure_stream, &proof_frame),
    )
    .await?;

    // 6. Receive the final Host authentication result.
    let response_frame = with_timeout(operation_timeout, read_frame(&mut secure_stream)).await?;

    validate_auth_frame(&response_frame, MessageKind::AuthResponse, AUTH_REQUEST_ID)?;

    let response = AuthResponsePayload::decode(&response_frame.payload)?;

    if response.status != AuthStatus::Success {
        return Err(status_error(response.status));
    }

    // Only return a usable authenticated stream after explicit success.
    Ok(AuthenticatedClient {
        stream: secure_stream,
        username: username.to_string(),
        key_id,
    })
}

/// Load a protected Client key file and authenticate with the Host.
pub async fn authenticate_with_key_file(
    transport_stream: BoxedStream,
    server_name: ServerName<'static>,
    tls_config: Arc<ClientConfig>,
    username: &str,
    key_path: impl AsRef<std::path::Path>,
    operation_timeout: Duration,
) -> io::Result<AuthenticatedClient> {
    let key_pair = myssh_auth::load_client_keypair(key_path)?;

    authenticate(
        transport_stream,
        server_name,
        tls_config,
        username,
        &key_pair,
        operation_timeout,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    use myssh_auth::{AuthProof, AuthServer, ClientKeyPair, TrustStore};
    use myssh_protocol::{
        read_frame, write_frame, AuthChallengePayload, AuthProofPayload, AuthRequestPayload,
        AuthResponsePayload, AuthStatus, Frame, MessageKind,
    };
    use myssh_security::{build_client_config, build_server_config, server_handshake};

    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::duplex;

    fn create_tls_configs() -> (Arc<rustls::ServerConfig>, Arc<ClientConfig>) {
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

    #[tokio::test]
    async fn completes_tls_and_ed25519_authentication() {
        let (server_tls, client_tls) = create_tls_configs();

        let client_key = ClientKeyPair::generate();

        let mut trust_store = TrustStore::new();
        trust_store
            .add("test-user", client_key.public_key_bytes())
            .unwrap();

        let mut auth_server = AuthServer::new(trust_store, Duration::from_secs(30));

        let (client_io, server_io) = duplex(64 * 1024);

        let server = async move {
            // 1. Host TLS handshake.
            let mut stream = server_handshake(Box::new(server_io), server_tls)
                .await
                .unwrap();

            // 2. Receive Client AuthRequest.
            let request_frame = read_frame(&mut stream).await.unwrap();

            assert_eq!(request_frame.header.kind, MessageKind::AuthRequest,);
            assert_eq!(request_frame.header.session_id, 0);

            let request = AuthRequestPayload::decode(&request_frame.payload).unwrap();

            // 3. Issue Host challenge.
            let challenge = auth_server
                .begin_auth(&request.username, &request.key_id)
                .unwrap();

            let challenge_payload = AuthChallengePayload {
                challenge_id: challenge.challenge_id,
                nonce: challenge.nonce,
                username: challenge.username,
                key_id: challenge.key_id,
                protocol_version: challenge.protocol_version,
            };

            let challenge_frame = Frame::new(
                MessageKind::AuthChallenge,
                0,
                request_frame.header.request_id,
                challenge_payload.encode().unwrap(),
            )
            .unwrap();

            write_frame(&mut stream, &challenge_frame).await.unwrap();

            // 4. Receive Client proof.
            let proof_frame = read_frame(&mut stream).await.unwrap();

            assert_eq!(proof_frame.header.kind, MessageKind::AuthProof,);
            assert_eq!(
                proof_frame.header.request_id,
                request_frame.header.request_id,
            );

            let proof_payload = AuthProofPayload::decode(&proof_frame.payload).unwrap();

            let proof = AuthProof {
                challenge_id: proof_payload.challenge_id,
                signature: proof_payload.signature,
            };

            // 5. Verify Ed25519 signature.
            let identity = auth_server.verify(&proof).unwrap();

            // 6. Send authentication success.
            let response = AuthResponsePayload {
                status: AuthStatus::Success,
            };

            let response_frame = Frame::new(
                MessageKind::AuthResponse,
                0,
                request_frame.header.request_id,
                response.encode(),
            )
            .unwrap();

            write_frame(&mut stream, &response_frame).await.unwrap();

            identity
        };

        let client = authenticate(
            Box::new(client_io),
            ServerName::try_from("localhost".to_string()).unwrap(),
            client_tls,
            "test-user",
            &client_key,
            Duration::from_secs(5),
        );

        let (server_result, client_result) = tokio::join!(server, client);

        let host_identity = server_result;

        let authenticated_client = client_result.unwrap();

        assert_eq!(host_identity.username, "test-user");
        assert_eq!(host_identity.key_id, client_key.key_id(),);

        assert_eq!(authenticated_client.username, "test-user",);
        assert_eq!(authenticated_client.key_id, client_key.key_id(),);
    }
}
