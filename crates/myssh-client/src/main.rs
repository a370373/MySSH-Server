use myssh_auth::{load_client_keypair, save_client_keypair, ClientKeyPair};
use myssh_client::connection::connect_and_authenticate;
use myssh_client::file_transfer::{download_file, upload_file};
use myssh_client::terminal::run_shell;
use myssh_security::build_client_config;
use myssh_transport_cloudflare::CloudflareTransport;

use rustls::pki_types::ServerName;

use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

struct Options {
    endpoint: Option<String>,
    tls_ca: Option<PathBuf>,
    identity: Option<PathBuf>,
    timeout: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            endpoint: None,
            tls_ca: None,
            identity: None,
            timeout: 30,
        }
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn print_usage() {
    println!(
        "MySSH - Lightweight remote shell and file transfer

USAGE:
  myssh keygen
  myssh keygen --output FILE
  myssh keygen --show-public FILE
  myssh [OPTIONS] shell USER@HOST
  myssh [OPTIONS] upload LOCAL_FILE USER@HOST:/REMOTE/PATH
  myssh [OPTIONS] download USER@HOST:/REMOTE/FILE LOCAL_PATH

OPTIONS:
  --endpoint ADDRESS   Local TCP endpoint exposed by cloudflared
  --tls-ca FILE        Trusted server certificate / CA bundle in PEM
  --identity FILE      Client private key file
  --timeout SECONDS    Connection/authentication timeout (default: 30)
  -h, --help           Show this help

EXAMPLES:
  myssh --endpoint 127.0.0.1:2222 --tls-ca server.pem --identity id.key shell admin@example.com

  myssh --endpoint 127.0.0.1:2222 --tls-ca server.pem --identity id.key upload ./file.txt admin@example.com:/home/admin/file.txt

  myssh --endpoint 127.0.0.1:2222 --tls-ca server.pem --identity id.key download admin@example.com:/home/admin/file.txt ./file.txt
"
    );
}

fn parse_arguments(args: Vec<String>) -> Result<(Options, Vec<String>), Box<dyn Error>> {
    let mut options = Options::default();
    let mut positional = Vec::new();

    let mut iter = args.into_iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--endpoint" => {
                options.endpoint = Some(
                    iter.next()
                        .ok_or_else(|| invalid_input("--endpoint requires an address"))?,
                );
            }
            "--tls-ca" => {
                options.tls_ca =
                    Some(PathBuf::from(iter.next().ok_or_else(|| {
                        invalid_input("--tls-ca requires a file path")
                    })?));
            }
            "--identity" => {
                options.identity =
                    Some(PathBuf::from(iter.next().ok_or_else(|| {
                        invalid_input("--identity requires a file path")
                    })?));
            }
            "--timeout" => {
                let value = iter
                    .next()
                    .ok_or_else(|| invalid_input("--timeout requires a number"))?;

                options.timeout = value.parse()?;

                if options.timeout == 0 {
                    return Err(invalid_input("--timeout must be greater than zero").into());
                }
            }
            _ if arg.starts_with('-') => {
                return Err(invalid_input(format!("Unknown option: {arg}")).into());
            }
            _ => positional.push(arg),
        }
    }

    Ok((options, positional))
}

fn parse_authority(value: &str) -> Result<(String, String), Box<dyn Error>> {
    let (username, host) = value
        .split_once('@')
        .ok_or_else(|| invalid_input("Expected USER@HOST"))?;

    if username.is_empty() || host.is_empty() {
        return Err(invalid_input("Username and host must not be empty").into());
    }

    Ok((username.to_string(), host.to_string()))
}

fn parse_remote_target(value: &str) -> Result<(String, String, String), Box<dyn Error>> {
    let (authority, remote_path) = value
        .split_once(":/")
        .ok_or_else(|| invalid_input("Expected USER@HOST:/ABSOLUTE/REMOTE/PATH"))?;

    let (username, host) = parse_authority(authority)?;

    Ok((username, host, format!("/{remote_path}")))
}

fn make_server_name(host: &str) -> Result<ServerName<'static>, Box<dyn Error>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }

    Ok(ServerName::try_from(host.to_string())?)
}

fn load_tls_config(path: &PathBuf) -> Result<Arc<rustls::ClientConfig>, Box<dyn Error>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let certificates = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;

    if certificates.is_empty() {
        return Err(invalid_input("TLS certificate file contains no certificates").into());
    }

    Ok(build_client_config(certificates)?)
}

async fn connect(
    options: &Options,
    username: &str,
    host: &str,
) -> Result<myssh_client::auth::AuthenticatedClient, Box<dyn Error>> {
    let endpoint = options
        .endpoint
        .as_deref()
        .ok_or_else(|| invalid_input("Missing --endpoint"))?;

    let tls_ca = options
        .tls_ca
        .as_ref()
        .ok_or_else(|| invalid_input("Missing --tls-ca"))?;

    let identity = options
        .identity
        .as_ref()
        .ok_or_else(|| invalid_input("Missing --identity"))?;

    let server_name = make_server_name(host)?;
    let tls_config = load_tls_config(tls_ca)?;

    let transport = CloudflareTransport;

    let client = connect_and_authenticate(
        &transport,
        endpoint,
        server_name,
        tls_config,
        username,
        identity,
        Duration::from_secs(options.timeout),
    )
    .await?;

    Ok(client)
}

enum KeygenAction {
    Generate(Option<PathBuf>),
    ShowPublic(PathBuf),
}

fn parse_keygen_args(args: &[String]) -> Result<KeygenAction, Box<dyn Error>> {
    match args {
        [] => Ok(KeygenAction::Generate(None)),

        [flag, path] if flag == "--output" => {
            if path.is_empty() {
                return Err(invalid_input("Output path cannot be empty").into());
            }

            Ok(KeygenAction::Generate(Some(PathBuf::from(path))))
        }

        [flag, path] if flag == "--show-public" => {
            if path.is_empty() {
                return Err(invalid_input("Identity path cannot be empty").into());
            }

            Ok(KeygenAction::ShowPublic(PathBuf::from(path)))
        }

        _ => Err(invalid_input("Usage: myssh keygen [--output FILE | --show-public FILE]").into()),
    }
}

fn print_keygen_usage() {
    println!(
        "MySSH identity key management\n\n\
         USAGE:\n\
           myssh keygen\n\
           myssh keygen --output FILE\n\
           myssh keygen --show-public FILE"
    );
}

fn default_identity_path() -> Result<PathBuf, Box<dyn Error>> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| invalid_input("HOME is not set; use --output FILE"))?;

    Ok(PathBuf::from(home).join(".myssh").join("id_ed25519"))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        let value = *byte;
        output.push(HEX[(value >> 4) as usize] as char);
        output.push(HEX[(value & 0x0f) as usize] as char);
    }

    output
}

fn run_keygen(args: &[String]) -> Result<(), Box<dyn Error>> {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print_keygen_usage();
        return Ok(());
    }

    match parse_keygen_args(args)? {
        KeygenAction::Generate(output_path) => {
            let path = match output_path {
                Some(path) => path,
                None => {
                    let path = default_identity_path()?;

                    let parent = path
                        .parent()
                        .ok_or_else(|| invalid_input("Invalid default identity path"))?;

                    fs::create_dir_all(parent)?;
                    path
                }
            };

            let keypair = ClientKeyPair::generate();

            // create_new 防止覆蓋既有私鑰。
            // Auth 模組負責安全權限與金鑰格式。
            save_client_keypair(&path, &keypair)?;

            println!("Ed25519 identity key generated.");
            println!("Private key: {}", path.display());
            println!("Key ID: {}", keypair.key_id());
            println!(
                "Show public key with: myssh keygen --show-public {}",
                path.display()
            );
        }

        KeygenAction::ShowPublic(path) => {
            let keypair = load_client_keypair(&path)?;
            let public_key_hex = bytes_to_hex(&keypair.public_key_bytes());

            println!("MySSH Ed25519 Public Key");
            println!("Key ID: {}", keypair.key_id());
            println!("Public Key (hex):");
            println!("{public_key_hex}");
        }
    }

    Ok(())
}

async fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Local identity management does not require a network connection.
    if matches!(args.first().map(String::as_str), Some("keygen")) {
        return run_keygen(&args[1..]);
    }

    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_usage();
        return Ok(());
    }

    let (options, positional) = parse_arguments(args)?;

    if positional.is_empty() {
        print_usage();
        return Err(invalid_input("Missing command").into());
    }

    match positional[0].as_str() {
        "shell" => {
            if positional.len() != 2 {
                return Err(invalid_input("Usage: myssh shell USER@HOST").into());
            }

            let (username, host) = parse_authority(&positional[1])?;
            let client = connect(&options, &username, &host).await?;

            run_shell(client).await?;
        }

        "upload" => {
            if positional.len() != 3 {
                return Err(
                    invalid_input("Usage: myssh upload LOCAL_FILE USER@HOST:/REMOTE/PATH").into(),
                );
            }

            let local_path = PathBuf::from(&positional[1]);

            let (username, host, remote_path) = parse_remote_target(&positional[2])?;

            let client = connect(&options, &username, &host).await?;

            upload_file(client, local_path, &remote_path).await?;

            println!("Upload completed: {remote_path}");
        }

        "download" => {
            if positional.len() != 3 {
                return Err(invalid_input(
                    "Usage: myssh download USER@HOST:/REMOTE/FILE LOCAL_PATH",
                )
                .into());
            }

            let (username, host, remote_path) = parse_remote_target(&positional[1])?;

            let local_path = PathBuf::from(&positional[2]);

            let client = connect(&options, &username, &host).await?;

            download_file(client, &remote_path, local_path).await?;

            println!("Download completed: {remote_path}");
        }

        command => {
            return Err(invalid_input(format!("Unknown command: {command}")).into());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cli_options() {
        let args = vec![
            "shell".to_string(),
            "admin@example.com".to_string(),
            "--endpoint".to_string(),
            "127.0.0.1:2222".to_string(),
            "--tls-ca".to_string(),
            "server.pem".to_string(),
            "--identity".to_string(),
            "id.key".to_string(),
            "--timeout".to_string(),
            "45".to_string(),
        ];

        let (options, positional) = parse_arguments(args).unwrap();

        assert_eq!(options.endpoint.as_deref(), Some("127.0.0.1:2222"));
        assert_eq!(options.tls_ca, Some(PathBuf::from("server.pem")));
        assert_eq!(options.identity, Some(PathBuf::from("id.key")));
        assert_eq!(options.timeout, 45);
        assert_eq!(positional, vec!["shell", "admin@example.com"]);
    }

    #[test]
    fn parses_username_and_host() {
        let (username, host) = parse_authority("admin@example.com").unwrap();

        assert_eq!(username, "admin");
        assert_eq!(host, "example.com");
    }

    #[test]
    fn rejects_invalid_authority() {
        assert!(parse_authority("example.com").is_err());
        assert!(parse_authority("@example.com").is_err());
        assert!(parse_authority("admin@").is_err());
    }

    #[test]
    fn parses_remote_target() {
        let (username, host, path) =
            parse_remote_target("admin@example.com:/home/admin/files/test.txt").unwrap();

        assert_eq!(username, "admin");
        assert_eq!(host, "example.com");
        assert_eq!(path, "/home/admin/files/test.txt");
    }

    #[test]
    fn rejects_invalid_remote_target() {
        assert!(parse_remote_target("admin@example.com").is_err());
        assert!(parse_remote_target("admin@example.com:relative/path").is_err());
    }

    #[test]
    fn rejects_zero_timeout() {
        let args = vec![
            "--timeout".to_string(),
            "0".to_string(),
            "shell".to_string(),
            "admin@example.com".to_string(),
        ];

        assert!(parse_arguments(args).is_err());
    }

    #[test]
    fn rejects_unknown_options() {
        let args = vec!["--unknown".to_string(), "value".to_string()];

        assert!(parse_arguments(args).is_err());
    }
}

#[cfg(test)]
mod keygen_tests {
    use super::*;

    #[test]
    fn parses_default_keygen() {
        let args: Vec<String> = vec![];
        assert!(matches!(
            parse_keygen_args(&args).unwrap(),
            KeygenAction::Generate(None)
        ));
    }

    #[test]
    fn parses_custom_output_path() {
        let args = vec!["--output".to_string(), "./identity.key".to_string()];

        match parse_keygen_args(&args).unwrap() {
            KeygenAction::Generate(Some(path)) => {
                assert_eq!(path, PathBuf::from("./identity.key"));
            }
            _ => panic!("Expected Generate action"),
        }
    }

    #[test]
    fn parses_show_public_path() {
        let args = vec!["--show-public".to_string(), "./identity.key".to_string()];

        match parse_keygen_args(&args).unwrap() {
            KeygenAction::ShowPublic(path) => {
                assert_eq!(path, PathBuf::from("./identity.key"));
            }
            _ => panic!("Expected ShowPublic action"),
        }
    }

    #[test]
    fn rejects_invalid_keygen_arguments() {
        assert!(parse_keygen_args(&["--unknown".to_string()]).is_err());
        assert!(parse_keygen_args(&["--output".to_string()]).is_err());
        assert!(parse_keygen_args(&[
            "--show-public".to_string(),
            "key".to_string(),
            "extra".to_string(),
        ])
        .is_err());
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("myssh: {error}");
        std::process::exit(1);
    }
}
