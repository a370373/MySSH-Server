use myssh_auth::{ClientKeyPair, TrustStore};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir().join(format!(
            "myssh-host-test-{}-{timestamp}-{id}",
            std::process::id()
        ));

        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_host(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_myssh-host"))
        .args(args)
        .output()
        .expect("failed to execute myssh-host")
}

fn make_keypair() -> ClientKeyPair {
    ClientKeyPair::from_bytes(&[7u8; 32])
}

fn public_key_hex(keypair: &ClientKeyPair) -> String {
    keypair
        .public_key_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn trust_store_path(dir: &TestDir) -> PathBuf {
    dir.path().join("trust.store")
}

#[test]
fn trust_init_creates_empty_store() {
    let dir = TestDir::new();
    let store_path = trust_store_path(&dir);
    let store_path = store_path.to_str().unwrap();

    let output = run_host(&["trust-init", "--trust-store", store_path]);

    assert!(
        output.status.success(),
        "trust-init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let store = TrustStore::load(store_path).unwrap();
    assert!(store.is_empty());
}

#[test]
fn trust_add_persists_public_key() {
    let dir = TestDir::new();
    let store_path = trust_store_path(&dir);
    let store_path = store_path.to_str().unwrap();

    run_host(&["trust-init", "--trust-store", store_path]);

    let keypair = make_keypair();
    let key_id = keypair.key_id();
    let public_key = public_key_hex(&keypair);

    let output = run_host(&[
        "trust-add",
        "--trust-store",
        store_path,
        "--username",
        "test-user",
        "--public-key-hex",
        &public_key,
    ]);

    assert!(
        output.status.success(),
        "trust-add failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let store = TrustStore::load(store_path).unwrap();

    assert_eq!(store.len(), 1);
    assert!(store.contains(&key_id));
}

#[test]
fn trust_add_is_idempotent_for_same_key_and_username() {
    let dir = TestDir::new();
    let store_path = trust_store_path(&dir);
    let store_path = store_path.to_str().unwrap();

    run_host(&["trust-init", "--trust-store", store_path]);

    let keypair = make_keypair();
    let key_id = keypair.key_id();
    let public_key = public_key_hex(&keypair);

    let args = [
        "trust-add",
        "--trust-store",
        store_path,
        "--username",
        "test-user",
        "--public-key-hex",
        &public_key,
    ];

    let first = run_host(&args);
    assert!(
        first.status.success(),
        "first trust-add failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let second = run_host(&args);
    assert!(
        second.status.success(),
        "repeated trust-add should be idempotent: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let store = TrustStore::load(store_path).unwrap();
    assert_eq!(store.len(), 1);
    assert!(store.contains(&key_id));
}

#[test]
fn trust_add_rejects_assigning_key_to_another_username() {
    let dir = TestDir::new();
    let store_path = trust_store_path(&dir);
    let store_path = store_path.to_str().unwrap();

    run_host(&["trust-init", "--trust-store", store_path]);

    let keypair = make_keypair();
    let key_id = keypair.key_id();
    let public_key = public_key_hex(&keypair);

    let first = run_host(&[
        "trust-add",
        "--trust-store",
        store_path,
        "--username",
        "test-user",
        "--public-key-hex",
        &public_key,
    ]);

    assert!(first.status.success());

    let second = run_host(&[
        "trust-add",
        "--trust-store",
        store_path,
        "--username",
        "another-user",
        "--public-key-hex",
        &public_key,
    ]);

    assert!(
        !second.status.success(),
        "the same key must not be assigned to another username"
    );

    let store = TrustStore::load(store_path).unwrap();
    assert_eq!(store.len(), 1);
    assert!(store.contains(&key_id));
}

#[test]
fn trust_remove_persists_revocation() {
    let dir = TestDir::new();
    let store_path = trust_store_path(&dir);
    let store_path = store_path.to_str().unwrap();

    run_host(&["trust-init", "--trust-store", store_path]);

    let keypair = make_keypair();
    let key_id = keypair.key_id();
    let public_key = public_key_hex(&keypair);

    let add = run_host(&[
        "trust-add",
        "--trust-store",
        store_path,
        "--username",
        "test-user",
        "--public-key-hex",
        &public_key,
    ]);

    assert!(add.status.success());

    let remove = run_host(&[
        "trust-remove",
        "--trust-store",
        store_path,
        "--key-id",
        &key_id,
    ]);

    assert!(
        remove.status.success(),
        "trust-remove failed: {}",
        String::from_utf8_lossy(&remove.stderr)
    );

    let store = TrustStore::load(store_path).unwrap();

    assert!(store.is_empty());
    assert!(!store.contains(&key_id));
}

#[test]
fn trust_init_refuses_to_overwrite_existing_store() {
    let dir = TestDir::new();
    let store_path = trust_store_path(&dir);
    let store_path = store_path.to_str().unwrap();

    run_host(&["trust-init", "--trust-store", store_path]);

    let keypair = make_keypair();
    let public_key = public_key_hex(&keypair);

    let add = run_host(&[
        "trust-add",
        "--trust-store",
        store_path,
        "--username",
        "test-user",
        "--public-key-hex",
        &public_key,
    ]);

    assert!(add.status.success());

    let second_init = run_host(&["trust-init", "--trust-store", store_path]);

    assert!(!second_init.status.success());

    let store = TrustStore::load(store_path).unwrap();
    assert_eq!(store.len(), 1);
}

#[cfg(unix)]
#[test]
fn trust_store_permissions_are_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TestDir::new();
    let store_path = trust_store_path(&dir);
    let store_path = store_path.to_str().unwrap();

    let output = run_host(&["trust-init", "--trust-store", store_path]);

    assert!(output.status.success());

    let metadata = fs::metadata(store_path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
}
