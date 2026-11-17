use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const PROTOCOL_VERSION: u16 = 1;

const SIGNATURE_DOMAIN: &[u8] = b"MYSSH-CLIENT-AUTH-ED25519-V1";

const KEY_ID_PREFIX: &str = "ed25519:";

const KEY_FILE_MAGIC: &[u8; 8] = b"MYSSHKEY";
const KEY_FILE_VERSION: u16 = 1;
const KEY_FILE_SIZE: usize = 74;

const TRUST_FILE_MAGIC: &[u8; 8] = b"MYSSHTS1";
const TRUST_FILE_VERSION: u16 = 1;
const MAX_TRUSTED_CLIENTS: usize = 1024;
const MAX_PENDING_CHALLENGES: usize = 1024;
const MAX_USERNAME_BYTES: usize = 256;
const MAX_TRUST_FILE_SIZE: usize = 14 + MAX_TRUSTED_CLIENTS * (2 + MAX_USERNAME_BYTES + 32);

#[derive(Debug)]
pub enum AuthError {
    InvalidPublicKey,
    InvalidPrivateKey,
    UnknownClientKey,
    UsernameNotAuthorized,
    InvalidChallenge,
    ChallengeExpired,
    PendingChallengeLimitReached,
    InvalidSignature,
    KeyAlreadyAssigned,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "Invalid public key"),
            Self::InvalidPrivateKey => write!(f, "Invalid private key"),
            Self::UnknownClientKey => write!(f, "Unknown client key"),
            Self::UsernameNotAuthorized => {
                write!(f, "Client is not authorized for this OS account")
            }
            Self::InvalidChallenge => {
                write!(f, "Invalid or already used challenge")
            }
            Self::ChallengeExpired => write!(f, "Challenge expired"),
            Self::PendingChallengeLimitReached => {
                write!(f, "Too many pending authentication challenges")
            }
            Self::InvalidSignature => write!(f, "Invalid client signature"),
            Self::KeyAlreadyAssigned => {
                write!(f, "Public key is already assigned to another OS account")
            }
        }
    }
}

impl std::error::Error for AuthError {}

/// Client-side Ed25519 key pair.
pub struct ClientKeyPair {
    signing_key: SigningKey,
}

impl ClientKeyPair {
    /// Generate a new Ed25519 key pair.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Restore a key pair from its 32-byte private seed.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    /// Export the 32-byte private seed.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Return the 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Return the public key identifier.
    pub fn key_id(&self) -> String {
        fingerprint(&self.public_key_bytes())
    }

    /// Sign a Host-issued challenge.
    pub fn sign_challenge(&self, challenge: &Challenge) -> Result<AuthProof, AuthError> {
        if self.key_id() != challenge.key_id {
            return Err(AuthError::InvalidChallenge);
        }

        let message = challenge.signing_message();
        let signature = self.signing_key.sign(&message);

        Ok(AuthProof {
            challenge_id: challenge.challenge_id,
            signature: signature.to_bytes(),
        })
    }
}

/// Generate a stable identifier from a public key.
fn fingerprint(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);

    let mut result = String::from(KEY_ID_PREFIX);

    for byte in digest {
        use std::fmt::Write;

        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }

    result
}

// ============================================================
// Client private-key storage
// ============================================================

/// Save a Client key pair to a new local file.
///
/// Existing files are never overwritten.
/// On Unix, the file is created with permission 0600.
pub fn save_client_keypair(path: impl AsRef<Path>, keypair: &ClientKeyPair) -> io::Result<()> {
    let path = path.as_ref();

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;

    let mut private_key = keypair.to_bytes();
    let public_key = keypair.public_key_bytes();

    let mut data = Vec::with_capacity(KEY_FILE_SIZE);

    data.extend_from_slice(KEY_FILE_MAGIC);
    data.extend_from_slice(&KEY_FILE_VERSION.to_be_bytes());
    data.extend_from_slice(&private_key);
    data.extend_from_slice(&public_key);

    let result = (|| -> io::Result<()> {
        file.write_all(&data)?;
        file.sync_all()?;
        Ok(())
    })();

    private_key.zeroize();
    data.zeroize();

    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }

    result
}

/// Load a Client key pair from a local file.
///
/// The stored public key is checked against the private key.
pub fn load_client_keypair(path: impl AsRef<Path>) -> io::Result<ClientKeyPair> {
    let path = path.as_ref();

    let metadata = fs::symlink_metadata(path)?;

    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Key path must be a regular file",
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = metadata.permissions().mode();

        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Private key permissions are too broad; expected 0600",
            ));
        }
    }

    if metadata.len() != KEY_FILE_SIZE as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid private key file size",
        ));
    }

    let mut file = OpenOptions::new().read(true).open(path)?;

    let mut data = Vec::with_capacity(KEY_FILE_SIZE);
    file.read_to_end(&mut data)?;

    if data.len() != KEY_FILE_SIZE {
        data.zeroize();

        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Incomplete private key file",
        ));
    }

    if &data[0..8] != KEY_FILE_MAGIC {
        data.zeroize();

        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid private key file magic",
        ));
    }

    let version = u16::from_be_bytes([data[8], data[9]]);

    if version != KEY_FILE_VERSION {
        data.zeroize();

        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unsupported private key file version",
        ));
    }

    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&data[10..42]);

    let mut stored_public_key = [0u8; 32];
    stored_public_key.copy_from_slice(&data[42..74]);

    let keypair = ClientKeyPair::from_bytes(&private_key);

    private_key.zeroize();
    data.zeroize();

    if keypair.public_key_bytes() != stored_public_key {
        stored_public_key.zeroize();

        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Private key and public key do not match",
        ));
    }

    stored_public_key.zeroize();

    Ok(keypair)
}

// ============================================================
// Host trust store
// ============================================================

#[derive(Clone)]
struct TrustedClient {
    username: String,
    verifying_key: VerifyingKey,
}

#[derive(Clone, Default)]
pub struct TrustStore {
    clients: HashMap<String, TrustedClient>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    pub fn add(
        &mut self,
        username: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<String, AuthError> {
        let username = username.into();

        if username.is_empty()
            || username.len() > MAX_USERNAME_BYTES
            || username.as_bytes().contains(&0)
        {
            return Err(AuthError::UsernameNotAuthorized);
        }

        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| AuthError::InvalidPublicKey)?;

        let key_id = fingerprint(&public_key);

        if let Some(existing) = self.clients.get(&key_id) {
            if existing.username == username {
                return Ok(key_id);
            }

            return Err(AuthError::KeyAlreadyAssigned);
        }

        if self.clients.len() >= MAX_TRUSTED_CLIENTS {
            return Err(AuthError::KeyAlreadyAssigned);
        }

        self.clients.insert(
            key_id.clone(),
            TrustedClient {
                username,
                verifying_key,
            },
        );

        Ok(key_id)
    }

    pub fn remove(&mut self, key_id: &str) -> bool {
        self.clients.remove(key_id).is_some()
    }

    pub fn contains(&self, key_id: &str) -> bool {
        self.clients.contains_key(key_id)
    }

    /// Save the trust store using a versioned binary format.
    ///
    /// The temporary file is created beside the destination and then
    /// atomically renamed into place. On Unix, its permissions are 0600.
    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();

        if self.clients.len() > MAX_TRUSTED_CLIENTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Too many trusted clients",
            ));
        }

        let mut entries: Vec<_> = self.clients.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        let mut data = Vec::new();
        data.extend_from_slice(TRUST_FILE_MAGIC);
        data.extend_from_slice(&TRUST_FILE_VERSION.to_be_bytes());
        data.extend_from_slice(&(entries.len() as u32).to_be_bytes());

        for (key_id, client) in entries {
            let username = client.username.as_bytes();

            if username.is_empty() || username.len() > MAX_USERNAME_BYTES || username.contains(&0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid username in trust store",
                ));
            }

            let public_key = client.verifying_key.to_bytes();

            if fingerprint(&public_key) != *key_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Trust store key identifier mismatch",
                ));
            }

            data.extend_from_slice(&(username.len() as u16).to_be_bytes());
            data.extend_from_slice(username);
            data.extend_from_slice(&public_key);
        }

        if data.len() > MAX_TRUST_FILE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Trust store exceeds maximum size",
            ));
        }

        let file_name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Invalid trust store path")
        })?;

        let parent = path.parent().unwrap_or_else(|| Path::new("."));

        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);

        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();

        let mut temp_name = file_name.to_os_string();
        temp_name.push(format!(".tmp-{suffix}"));
        let temp_path = parent.join(temp_name);

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(&temp_path)?;

        let write_result = (|| -> io::Result<()> {
            file.write_all(&data)?;
            file.sync_all()?;
            drop(file);

            fs::rename(&temp_path, path)?;

            // Sync the containing directory where supported.
            #[cfg(unix)]
            {
                let directory = OpenOptions::new().read(true).open(parent)?;
                directory.sync_all()?;
            }

            Ok(())
        })();

        data.zeroize();

        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }

        write_result
    }

    /// Load and validate a persisted trust store.
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path)?;

        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Trust store path must be a regular file",
            ));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();

            if mode & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Trust store permissions are too broad; expected 0600",
                ));
            }
        }

        if metadata.len() > MAX_TRUST_FILE_SIZE as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Trust store file is too large",
            ));
        }

        let file = OpenOptions::new().read(true).open(path)?;
        let mut data = Vec::new();

        file.take((MAX_TRUST_FILE_SIZE + 1) as u64)
            .read_to_end(&mut data)?;

        let result = Self::decode(&data);
        data.zeroize();
        result
    }

    fn decode(data: &[u8]) -> io::Result<Self> {
        fn invalid(message: &'static str) -> io::Error {
            io::Error::new(io::ErrorKind::InvalidData, message)
        }

        if data.len() < 14 || data.len() > MAX_TRUST_FILE_SIZE {
            return Err(invalid("Invalid trust store size"));
        }

        if &data[..8] != TRUST_FILE_MAGIC {
            return Err(invalid("Invalid trust store magic"));
        }

        let version = u16::from_be_bytes([data[8], data[9]]);
        if version != TRUST_FILE_VERSION {
            return Err(invalid("Unsupported trust store version"));
        }

        let count = u32::from_be_bytes([data[10], data[11], data[12], data[13]]) as usize;

        if count > MAX_TRUSTED_CLIENTS {
            return Err(invalid("Too many trusted clients"));
        }

        let mut offset = 14usize;
        let mut store = TrustStore::new();

        for _ in 0..count {
            if offset + 2 > data.len() {
                return Err(invalid("Truncated username length"));
            }

            let username_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if username_len == 0 || username_len > MAX_USERNAME_BYTES {
                return Err(invalid("Invalid username length"));
            }

            let record_end = offset
                .checked_add(username_len)
                .and_then(|v| v.checked_add(32))
                .ok_or_else(|| invalid("Trust store length overflow"))?;

            if record_end > data.len() {
                return Err(invalid("Truncated trust store record"));
            }

            let username = std::str::from_utf8(&data[offset..offset + username_len])
                .map_err(|_| invalid("Username is not valid UTF-8"))?
                .to_string();

            if username.as_bytes().contains(&0) {
                return Err(invalid("Username contains a NUL byte"));
            }

            offset += username_len;

            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;

            store
                .add(username, public_key)
                .map_err(|_| invalid("Invalid or conflicting trust record"))?;
        }

        if offset != data.len() {
            return Err(invalid("Unexpected trailing trust store data"));
        }

        Ok(store)
    }

    /// Add a client and persist the change.
    /// The in-memory state is rolled back if saving fails.
    pub fn add_and_save(
        &mut self,
        path: impl AsRef<Path>,
        username: impl Into<String>,
        public_key: [u8; 32],
    ) -> io::Result<String> {
        let previous = self.clone();

        self.add(username, public_key)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;

        if let Err(error) = self.save(path) {
            *self = previous;
            return Err(error);
        }

        let key_id = fingerprint(&public_key);
        Ok(key_id)
    }

    /// Revoke a client and persist the change.
    /// The in-memory state is rolled back if saving fails.
    pub fn remove_and_save(&mut self, path: impl AsRef<Path>, key_id: &str) -> io::Result<bool> {
        let previous = self.clone();

        if !self.remove(key_id) {
            return Ok(false);
        }

        if let Err(error) = self.save(path) {
            *self = previous;
            return Err(error);
        }

        Ok(true)
    }
}

// ============================================================
// Challenge-Response
// ============================================================

#[derive(Clone, Debug)]
pub struct Challenge {
    pub challenge_id: [u8; 16],
    pub nonce: [u8; 32],
    pub username: String,
    pub key_id: String,
    pub protocol_version: u16,
}

impl Challenge {
    fn signing_message(&self) -> Vec<u8> {
        let mut message = Vec::new();

        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(&self.protocol_version.to_be_bytes());

        message.extend_from_slice(&(self.username.len() as u32).to_be_bytes());
        message.extend_from_slice(self.username.as_bytes());

        message.extend_from_slice(&(self.key_id.len() as u32).to_be_bytes());
        message.extend_from_slice(self.key_id.as_bytes());

        message.extend_from_slice(&self.challenge_id);
        message.extend_from_slice(&self.nonce);

        message
    }
}

#[derive(Clone, Debug)]
pub struct AuthProof {
    pub challenge_id: [u8; 16],
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedIdentity {
    pub username: String,
    pub key_id: String,
}

struct PendingChallenge {
    challenge: Challenge,
    issued_at: Instant,
}

pub struct AuthServer {
    trust_store: TrustStore,
    pending: HashMap<[u8; 16], PendingChallenge>,
    challenge_ttl: Duration,
}

impl AuthServer {
    pub fn new(trust_store: TrustStore, challenge_ttl: Duration) -> Self {
        Self {
            trust_store,
            pending: HashMap::new(),
            challenge_ttl,
        }
    }

    pub fn begin_auth(&mut self, username: &str, key_id: &str) -> Result<Challenge, AuthError> {
        let trusted = self
            .trust_store
            .clients
            .get(key_id)
            .ok_or(AuthError::UnknownClientKey)?;

        if trusted.username != username {
            return Err(AuthError::UsernameNotAuthorized);
        }

        // Remove expired challenges before enforcing the limit.
        self.pending
            .retain(|_, pending| pending.issued_at.elapsed() < self.challenge_ttl);

        if self.pending.len() >= MAX_PENDING_CHALLENGES {
            return Err(AuthError::PendingChallengeLimitReached);
        }

        let mut challenge_id = [0u8; 16];

        loop {
            OsRng.fill_bytes(&mut challenge_id);

            if !self.pending.contains_key(&challenge_id) {
                break;
            }
        }

        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        let challenge = Challenge {
            challenge_id,
            nonce,
            username: username.to_string(),
            key_id: key_id.to_string(),
            protocol_version: PROTOCOL_VERSION,
        };

        self.pending.insert(
            challenge_id,
            PendingChallenge {
                challenge: challenge.clone(),
                issued_at: Instant::now(),
            },
        );

        Ok(challenge)
    }

    pub fn verify(&mut self, proof: &AuthProof) -> Result<AuthenticatedIdentity, AuthError> {
        let pending = self
            .pending
            .remove(&proof.challenge_id)
            .ok_or(AuthError::InvalidChallenge)?;

        if pending.issued_at.elapsed() >= self.challenge_ttl {
            return Err(AuthError::ChallengeExpired);
        }

        let challenge = pending.challenge;

        let trusted = self
            .trust_store
            .clients
            .get(&challenge.key_id)
            .ok_or(AuthError::UnknownClientKey)?;

        if trusted.username != challenge.username {
            return Err(AuthError::UsernameNotAuthorized);
        }

        let signature = Signature::from_bytes(&proof.signature);
        let message = challenge.signing_message();

        trusted
            .verifying_key
            .verify(&message, &signature)
            .map_err(|_| AuthError::InvalidSignature)?;

        Ok(AuthenticatedIdentity {
            username: challenge.username,
            key_id: challenge.key_id,
        })
    }

    pub fn revoke(&mut self, key_id: &str) -> bool {
        let removed = self.trust_store.remove(key_id);

        // Revoke all outstanding challenges issued to this key.
        self.pending
            .retain(|_, pending| pending.challenge.key_id != key_id);

        removed
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "myssh-{label}-{}-{}.key",
            std::process::id(),
            ClientKeyPair::generate().key_id()
        ))
    }

    #[test]
    fn generates_ed25519_key_pair() {
        let client = ClientKeyPair::generate();

        assert_eq!(client.public_key_bytes().len(), 32);
        assert_eq!(client.to_bytes().len(), 32);
        assert!(client.key_id().starts_with(KEY_ID_PREFIX));
    }

    #[test]
    fn restores_key_pair() {
        let original = ClientKeyPair::generate();
        let restored = ClientKeyPair::from_bytes(&original.to_bytes());

        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());

        assert_eq!(original.key_id(), restored.key_id());
    }

    #[test]
    fn accepts_authorized_client() {
        let client = ClientKeyPair::generate();
        let mut trust_store = TrustStore::new();

        let key_id = trust_store.add("admin", client.public_key_bytes()).unwrap();

        let mut server = AuthServer::new(trust_store, Duration::from_secs(30));

        let challenge = server.begin_auth("admin", &key_id).unwrap();
        let proof = client.sign_challenge(&challenge).unwrap();
        let identity = server.verify(&proof).unwrap();

        assert_eq!(identity.username, "admin");
        assert_eq!(identity.key_id, key_id);
    }

    #[test]
    fn rejects_unknown_client_key() {
        let client = ClientKeyPair::generate();

        let mut server = AuthServer::new(TrustStore::new(), Duration::from_secs(30));

        assert!(matches!(
            server.begin_auth("admin", &client.key_id()),
            Err(AuthError::UnknownClientKey)
        ));
    }

    #[test]
    fn rejects_wrong_os_username() {
        let client = ClientKeyPair::generate();
        let mut trust_store = TrustStore::new();

        let key_id = trust_store.add("admin", client.public_key_bytes()).unwrap();

        let mut server = AuthServer::new(trust_store, Duration::from_secs(30));

        assert!(matches!(
            server.begin_auth("root", &key_id),
            Err(AuthError::UsernameNotAuthorized)
        ));
    }

    #[test]
    fn rejects_modified_signature() {
        let client = ClientKeyPair::generate();
        let mut trust_store = TrustStore::new();

        let key_id = trust_store.add("admin", client.public_key_bytes()).unwrap();

        let mut server = AuthServer::new(trust_store, Duration::from_secs(30));

        let challenge = server.begin_auth("admin", &key_id).unwrap();
        let mut proof = client.sign_challenge(&challenge).unwrap();

        proof.signature[0] ^= 1;

        assert!(matches!(
            server.verify(&proof),
            Err(AuthError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_replayed_challenge() {
        let client = ClientKeyPair::generate();
        let mut trust_store = TrustStore::new();

        let key_id = trust_store.add("admin", client.public_key_bytes()).unwrap();

        let mut server = AuthServer::new(trust_store, Duration::from_secs(30));

        let challenge = server.begin_auth("admin", &key_id).unwrap();
        let proof = client.sign_challenge(&challenge).unwrap();

        assert!(server.verify(&proof).is_ok());

        assert!(matches!(
            server.verify(&proof),
            Err(AuthError::InvalidChallenge)
        ));
    }

    #[test]
    fn rejects_expired_challenge() {
        let client = ClientKeyPair::generate();
        let mut trust_store = TrustStore::new();

        let key_id = trust_store.add("admin", client.public_key_bytes()).unwrap();

        let mut server = AuthServer::new(trust_store, Duration::ZERO);

        let challenge = server.begin_auth("admin", &key_id).unwrap();
        let proof = client.sign_challenge(&challenge).unwrap();

        assert!(matches!(
            server.verify(&proof),
            Err(AuthError::ChallengeExpired)
        ));
    }

    #[test]
    fn enforces_pending_challenge_limit() {
        let client = ClientKeyPair::generate();
        let mut trust_store = TrustStore::new();

        let key_id = trust_store.add("admin", client.public_key_bytes()).unwrap();

        let mut server = AuthServer::new(trust_store, Duration::from_secs(300));

        for _ in 0..MAX_PENDING_CHALLENGES {
            server.begin_auth("admin", &key_id).unwrap();
        }

        assert_eq!(server.pending.len(), MAX_PENDING_CHALLENGES);

        assert!(matches!(
            server.begin_auth("admin", &key_id),
            Err(AuthError::PendingChallengeLimitReached)
        ));

        assert_eq!(server.pending.len(), MAX_PENDING_CHALLENGES);
    }

    #[test]
    fn rejects_key_after_revocation() {
        let client = ClientKeyPair::generate();
        let mut trust_store = TrustStore::new();

        let key_id = trust_store.add("admin", client.public_key_bytes()).unwrap();

        let mut server = AuthServer::new(trust_store, Duration::from_secs(30));

        let challenge = server.begin_auth("admin", &key_id).unwrap();
        let proof = client.sign_challenge(&challenge).unwrap();

        assert!(server.revoke(&key_id));
        assert!(server.pending.is_empty());

        assert!(matches!(
            server.verify(&proof),
            Err(AuthError::InvalidChallenge)
        ));
    }

    #[test]
    fn saves_and_loads_client_keypair() {
        let original = ClientKeyPair::generate();
        let path = unique_temp_path("save-load");

        let _ = fs::remove_file(&path);

        save_client_keypair(&path, &original).unwrap();

        let loaded = load_client_keypair(&path).unwrap();

        assert_eq!(original.public_key_bytes(), loaded.public_key_bytes());

        assert_eq!(original.key_id(), loaded.key_id());

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn refuses_to_overwrite_existing_key_file() {
        let first = ClientKeyPair::generate();
        let second = ClientKeyPair::generate();
        let path = unique_temp_path("no-overwrite");

        let _ = fs::remove_file(&path);

        save_client_keypair(&path, &first).unwrap();

        assert!(save_client_keypair(&path, &second).is_err());

        let loaded = load_client_keypair(&path).unwrap();

        assert_eq!(first.public_key_bytes(), loaded.public_key_bytes());

        fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn creates_private_key_file_with_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let keypair = ClientKeyPair::generate();
        let path = unique_temp_path("permissions");

        let _ = fs::remove_file(&path);

        save_client_keypair(&path, &keypair).unwrap();

        let metadata = fs::metadata(&path).unwrap();

        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn trust_store_round_trip() {
        let client = ClientKeyPair::generate();
        let path = unique_temp_path("trust-round-trip");

        let _ = fs::remove_file(&path);

        let mut store = TrustStore::new();
        let key_id = store.add("alice", client.public_key_bytes()).unwrap();

        store.save(&path).unwrap();

        let loaded = TrustStore::load(&path).unwrap();

        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains(&key_id));

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn trust_store_rejects_account_rebinding() {
        let client = ClientKeyPair::generate();
        let mut store = TrustStore::new();

        store.add("alice", client.public_key_bytes()).unwrap();

        assert!(matches!(
            store.add("bob", client.public_key_bytes()),
            Err(AuthError::KeyAlreadyAssigned)
        ));

        assert_eq!(store.len(), 1);
    }

    #[test]
    fn trust_store_allows_idempotent_add() {
        let client = ClientKeyPair::generate();
        let mut store = TrustStore::new();

        let first = store.add("alice", client.public_key_bytes()).unwrap();
        let second = store.add("alice", client.public_key_bytes()).unwrap();

        assert_eq!(first, second);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn trust_store_persists_revocation() {
        let client = ClientKeyPair::generate();
        let path = unique_temp_path("trust-revoke");

        let _ = fs::remove_file(&path);

        let mut store = TrustStore::new();
        let key_id = store.add("alice", client.public_key_bytes()).unwrap();

        store.save(&path).unwrap();
        assert!(store.remove_and_save(&path, &key_id).unwrap());

        let loaded = TrustStore::load(&path).unwrap();

        assert!(!loaded.contains(&key_id));
        assert!(loaded.is_empty());

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn trust_store_rejects_corrupted_file() {
        let path = unique_temp_path("trust-corrupt");

        let _ = fs::remove_file(&path);
        fs::write(&path, b"NOT-A-TRUST-STORE").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert!(TrustStore::load(&path).is_err());

        fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn trust_store_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = unique_temp_path("trust-permissions");
        let _ = fs::remove_file(&path);

        TrustStore::new().save(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        fs::remove_file(&path).unwrap();
    }
}
