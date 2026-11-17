pub mod auth_bridge;
pub mod auth_connection;
pub mod file_transfer;
pub mod file_transfer_session;
pub mod pty;
pub mod server;
pub mod shell_session;
pub mod terminal_bridge;

use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::Path;
use std::time::Duration;

use myssh_auth::{AuthServer, TrustStore};
use myssh_security::build_server_config;
use myssh_transport_cloudflare::CloudflareTransport;

use crate::file_transfer::HostFileStore;
use crate::server::run_server_with_shutdown;

type AppResult<T> = Result<T, Box<dyn Error>>;

const DEFAULT_MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_OPERATION_TIMEOUT: u64 = 30;
const GRACEFUL_SHUTDOWN_TIMEOUT: u64 = 5;
const CHALLENGE_TTL: u64 = 30;

fn print_help() {
    println!(
        r#"MySSH Host

Usage:
  myssh-host serve \
    --listen ADDRESS \
    --tls-cert FILE \
    --tls-key FILE \
    --trust-store FILE \
    --file-root DIRECTORY \
    [--max-file-size BYTES] \
    [--operation-timeout SECONDS]

  myssh-host trust-init --trust-store FILE

  myssh-host trust-add \
    --trust-store FILE \
    --username USERNAME \
    --public-key-hex HEX

  myssh-host trust-remove \
    --trust-store FILE \
    --key-id KEY_ID

  myssh-host --help

Commands:
  serve          Start the MySSH Host service.
  trust-init     Create an empty trust store.
  trust-add      Add an Ed25519 client public key.
  trust-remove   Revoke a trusted client key.

Notes:
  - The trust store must have Unix permissions 0600.
  - An empty trust store cannot be used to start the service.
  - The file root directory must already exist.
  - TLS certificate and private key must be PEM encoded.
  - The current Cloudflare adapter listens on a local TCP endpoint.
    It does not create or manage a Cloudflare Tunnel."#
    );
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn parse_options(args: &[String], allowed: &[&str]) -> AppResult<HashMap<String, String>> {
    let mut options = HashMap::new();
    let mut index = 0;

    while index < args.len() {
        let key = &args[index];

        if !key.starts_with("--") {
            return Err(invalid_input(format!("Unexpected argument: {key}")).into());
        }

        if !allowed.contains(&key.as_str()) {
            return Err(invalid_input(format!("Unknown option: {key}")).into());
        }

        if options.contains_key(key) {
            return Err(invalid_input(format!("Duplicate option: {key}")).into());
        }

        index += 1;

        if index >= args.len() || args[index].starts_with("--") {
            return Err(invalid_input(format!("Missing value for {key}")).into());
        }

        options.insert(key.clone(), args[index].clone());
        index += 1;
    }

    Ok(options)
}

fn required(options: &HashMap<String, String>, key: &str) -> AppResult<String> {
    options
        .get(key)
        .cloned()
        .ok_or_else(|| invalid_input(format!("Required option missing: {key}")).into())
}

fn parse_public_key_hex(value: &str) -> AppResult<[u8; 32]> {
    if value.len() != 64 {
        return Err(invalid_input(
            "Ed25519 public key must contain exactly 64 hexadecimal characters",
        )
        .into());
    }

    let mut result = [0u8; 32];

    for (index, byte) in result.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| invalid_input("Public key contains invalid hexadecimal data"))?;
    }

    Ok(result)
}

fn initialize_trust_store(path: &Path) -> AppResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(
                invalid_input("Trust store already exists; refusing to overwrite it").into(),
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    TrustStore::new().save(path)?;

    println!("Trust store created: {}", path.display());
    println!("No clients are trusted yet.");
    Ok(())
}

fn add_trusted_key(path: &Path, username: &str, public_key_hex: &str) -> AppResult<()> {
    let public_key = parse_public_key_hex(public_key_hex)?;
    let mut trust_store = TrustStore::load(path)?;

    let key_id = trust_store.add_and_save(path, username, public_key)?;

    println!("Trusted client added.");
    println!("Username: {username}");
    println!("Key ID: {key_id}");

    Ok(())
}

fn remove_trusted_key(path: &Path, key_id: &str) -> AppResult<()> {
    let mut trust_store = TrustStore::load(path)?;

    if trust_store.remove_and_save(path, key_id)? {
        println!("Trusted key revoked: {key_id}");
    } else {
        println!("Key not found: {key_id}");
    }

    Ok(())
}

fn load_tls_config(
    certificate_path: &Path,
    private_key_path: &Path,
) -> AppResult<std::sync::Arc<rustls::ServerConfig>> {
    let certificate_file = File::open(certificate_path)?;
    let mut certificate_reader = BufReader::new(certificate_file);

    let certificates =
        rustls_pemfile::certs(&mut certificate_reader).collect::<Result<Vec<_>, _>>()?;

    if certificates.is_empty() {
        return Err(invalid_input("TLS certificate file contains no certificates").into());
    }

    let private_key_file = File::open(private_key_path)?;
    let mut private_key_reader = BufReader::new(private_key_file);

    let private_key = rustls_pemfile::private_key(&mut private_key_reader)?
        .ok_or_else(|| invalid_input("TLS private key was not found in PEM file"))?;

    Ok(build_server_config(certificates, private_key)?)
}

async fn serve(args: &[String]) -> AppResult<()> {
    let options = parse_options(
        args,
        &[
            "--listen",
            "--tls-cert",
            "--tls-key",
            "--trust-store",
            "--file-root",
            "--max-file-size",
            "--operation-timeout",
        ],
    )?;

    let listen = required(&options, "--listen")?;
    let certificate_path = required(&options, "--tls-cert")?;
    let private_key_path = required(&options, "--tls-key")?;
    let trust_store_path = required(&options, "--trust-store")?;
    let file_root = required(&options, "--file-root")?;

    let max_file_size = options
        .get("--max-file-size")
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(DEFAULT_MAX_FILE_SIZE);

    let operation_timeout = options
        .get("--operation-timeout")
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(DEFAULT_OPERATION_TIMEOUT);

    if operation_timeout == 0 {
        return Err(invalid_input("--operation-timeout must be greater than zero").into());
    }

    if max_file_size == 0 {
        return Err(invalid_input("--max-file-size must be greater than zero").into());
    }

    let trust_store = TrustStore::load(&trust_store_path)?;

    if trust_store.is_empty() {
        return Err(invalid_input(
            "Trust store is empty; add at least one client key before starting Host",
        )
        .into());
    }

    let tls_config = load_tls_config(Path::new(&certificate_path), Path::new(&private_key_path))?;

    let file_store = HostFileStore::new(&file_root, max_file_size)?;

    let auth_server = AuthServer::new(trust_store, Duration::from_secs(CHALLENGE_TTL));

    let transport = CloudflareTransport;

    println!("MySSH Host starting");
    println!("Listen endpoint: {listen}");
    println!("File root: {}", file_store.root().display());
    println!("Maximum file size: {} bytes", file_store.max_file_size());
    println!("Trusted clients: enabled");
    println!("Press Ctrl+C to stop.");

    let shutdown = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                println!("\nShutdown signal received.");
            }
            Err(error) => {
                eprintln!("Could not listen for Ctrl+C: {error}");
            }
        }
    };

    run_server_with_shutdown(
        &transport,
        &listen,
        tls_config,
        auth_server,
        file_store,
        Duration::from_secs(operation_timeout),
        Duration::from_secs(GRACEFUL_SHUTDOWN_TIMEOUT),
        shutdown,
    )
    .await?;

    println!("MySSH Host stopped.");
    Ok(())
}

async fn run() -> AppResult<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
        print_help();
        return Ok(());
    }

    match args[0].as_str() {
        "serve" => serve(&args[1..]).await,

        "trust-init" => {
            let options = parse_options(&args[1..], &["--trust-store"])?;
            let path = required(&options, "--trust-store")?;
            initialize_trust_store(Path::new(&path))
        }

        "trust-add" => {
            let options = parse_options(
                &args[1..],
                &["--trust-store", "--username", "--public-key-hex"],
            )?;

            let path = required(&options, "--trust-store")?;
            let username = required(&options, "--username")?;
            let public_key = required(&options, "--public-key-hex")?;

            add_trusted_key(Path::new(&path), &username, &public_key)
        }

        "trust-remove" => {
            let options = parse_options(&args[1..], &["--trust-store", "--key-id"])?;

            let path = required(&options, "--trust-store")?;
            let key_id = required(&options, "--key-id")?;

            remove_trusted_key(Path::new(&path), &key_id)
        }

        command => Err(invalid_input(format!(
            "Unknown command: {command}\nRun `myssh-host --help` for usage."
        ))
        .into()),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("MySSH Host error: {error}");
        std::process::exit(1);
    }
}
