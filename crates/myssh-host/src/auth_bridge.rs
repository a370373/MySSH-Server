use std::io;

use myssh_auth::{AuthProof, AuthServer, AuthenticatedIdentity};
use myssh_protocol::{AuthChallengePayload, AuthProofPayload, AuthRequestPayload};

/// Convert an incoming Protocol AuthRequest into an Auth challenge.
///
/// The AuthServer checks whether the requested key is trusted and
/// whether it is authorized for the requested OS username.
pub fn issue_challenge(
    auth_server: &mut AuthServer,
    request: &AuthRequestPayload,
) -> io::Result<AuthChallengePayload> {
    let challenge = auth_server
        .begin_auth(&request.username, &request.key_id)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Client authentication request denied: {error}"),
            )
        })?;

    let payload = AuthChallengePayload {
        challenge_id: challenge.challenge_id,
        nonce: challenge.nonce,
        username: challenge.username,
        key_id: challenge.key_id,
        protocol_version: challenge.protocol_version,
    };

    // Validate that the generated challenge can be encoded before
    // allowing it to leave the Host.
    payload.encode()?;

    Ok(payload)
}

/// Verify a Protocol AuthProof using the AuthServer.
///
/// AuthServer consumes the pending challenge during verification.
/// A challenge therefore cannot be successfully replayed.
pub fn verify_proof(
    auth_server: &mut AuthServer,
    proof_payload: &AuthProofPayload,
) -> io::Result<AuthenticatedIdentity> {
    let proof = AuthProof {
        challenge_id: proof_payload.challenge_id,
        signature: proof_payload.signature,
    };

    auth_server.verify(&proof).map_err(|error| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Client authentication failed: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use myssh_auth::{ClientKeyPair, TrustStore};
    use myssh_protocol::{AuthChallengePayload, AuthProofPayload, AuthRequestPayload};

    fn create_auth_server() -> (AuthServer, ClientKeyPair) {
        let client_key = ClientKeyPair::generate();

        let mut trust_store = TrustStore::new();
        trust_store
            .add("test-user", client_key.public_key_bytes())
            .unwrap();

        let auth_server = AuthServer::new(trust_store, Duration::from_secs(30));

        (auth_server, client_key)
    }

    fn create_request(client_key: &ClientKeyPair) -> AuthRequestPayload {
        AuthRequestPayload {
            username: "test-user".to_string(),
            key_id: client_key.key_id(),
        }
    }

    fn sign_challenge(
        client_key: &ClientKeyPair,
        payload: &AuthChallengePayload,
    ) -> AuthProofPayload {
        // Reconstruct the Auth crate's Challenge from the wire payload.
        let challenge = myssh_auth::Challenge {
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

    #[test]
    fn accepts_authorized_client() {
        let (mut auth_server, client_key) = create_auth_server();
        let request = create_request(&client_key);

        let challenge_payload = issue_challenge(&mut auth_server, &request).unwrap();

        // Exercise the actual Protocol encoding and decoding boundary.
        let encoded = challenge_payload.encode().unwrap();
        let decoded = AuthChallengePayload::decode(&encoded).unwrap();

        let proof_payload = sign_challenge(&client_key, &decoded);

        let encoded_proof = proof_payload.encode();
        let decoded_proof = AuthProofPayload::decode(&encoded_proof).unwrap();

        let identity = verify_proof(&mut auth_server, &decoded_proof).unwrap();

        assert_eq!(identity.username, "test-user");
        assert_eq!(identity.key_id, client_key.key_id());
    }

    #[test]
    fn rejects_unauthorized_username() {
        let (mut auth_server, client_key) = create_auth_server();

        let request = AuthRequestPayload {
            username: "another-user".to_string(),
            key_id: client_key.key_id(),
        };

        let result = issue_challenge(&mut auth_server, &request);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_signature() {
        let (mut auth_server, client_key) = create_auth_server();
        let request = create_request(&client_key);

        let challenge = issue_challenge(&mut auth_server, &request).unwrap();

        let mut proof = sign_challenge(&client_key, &challenge);
        proof.signature[0] ^= 0x80;

        let result = verify_proof(&mut auth_server, &proof);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_replayed_challenge() {
        let (mut auth_server, client_key) = create_auth_server();
        let request = create_request(&client_key);

        let challenge = issue_challenge(&mut auth_server, &request).unwrap();

        let proof = sign_challenge(&client_key, &challenge);

        let first = verify_proof(&mut auth_server, &proof);
        assert!(first.is_ok());

        let second = verify_proof(&mut auth_server, &proof);
        assert!(second.is_err());
    }
}
