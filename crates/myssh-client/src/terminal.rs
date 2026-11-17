use std::io::{self, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal;

use myssh_core::Connection;
use myssh_protocol::{
    MessageKind, SessionClosePayload, SessionOpenPayload, SessionOpenStatus, SessionOpenedPayload,
    SessionResizePayload, SessionType,
};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::auth::AuthenticatedClient;

const INPUT_QUEUE_CAPACITY: usize = 64;
const OUTPUT_QUEUE_CAPACITY: usize = 64;

enum TerminalInput {
    Data(Vec<u8>),
    Resize(u16, u16),
}

struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn encode_key(key: KeyEvent) -> Option<Vec<u8>> {
    if key.kind == KeyEventKind::Release {
        return None;
    }

    let control = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);

    let mut bytes = if control {
        match key.code {
            KeyCode::Char(c) if c.is_ascii_alphabetic() => {
                vec![c.to_ascii_lowercase() as u8 - b'a' + 1]
            }
            KeyCode::Char('@') | KeyCode::Char(' ') => vec![0],
            KeyCode::Char('[') => vec![0x1b],
            KeyCode::Char('\\') => vec![0x1c],
            KeyCode::Char(']') => vec![0x1d],
            KeyCode::Char('^') => vec![0x1e],
            KeyCode::Char('_') => vec![0x1f],
            _ => return None,
        }
    } else {
        match key.code {
            KeyCode::Char(c) => {
                let mut buffer = [0u8; 4];
                c.encode_utf8(&mut buffer).as_bytes().to_vec()
            }
            KeyCode::Enter => vec![b'\r'],
            KeyCode::Backspace => vec![0x7f],
            KeyCode::Tab => vec![b'\t'],
            KeyCode::BackTab => b"\x1b[Z".to_vec(),
            KeyCode::Esc => vec![0x1b],
            KeyCode::Up => b"\x1b[A".to_vec(),
            KeyCode::Down => b"\x1b[B".to_vec(),
            KeyCode::Right => b"\x1b[C".to_vec(),
            KeyCode::Left => b"\x1b[D".to_vec(),
            KeyCode::Home => b"\x1b[H".to_vec(),
            KeyCode::End => b"\x1b[F".to_vec(),
            KeyCode::Insert => b"\x1b[2~".to_vec(),
            KeyCode::Delete => b"\x1b[3~".to_vec(),
            KeyCode::PageUp => b"\x1b[5~".to_vec(),
            KeyCode::PageDown => b"\x1b[6~".to_vec(),
            KeyCode::F(n) => {
                let sequence = match n {
                    1 => "\x1bOP".to_string(),
                    2 => "\x1bOQ".to_string(),
                    3 => "\x1bOR".to_string(),
                    4 => "\x1bOS".to_string(),
                    5 => "\x1b[15~".to_string(),
                    6 => "\x1b[17~".to_string(),
                    7 => "\x1b[18~".to_string(),
                    8 => "\x1b[19~".to_string(),
                    9 => "\x1b[20~".to_string(),
                    10 => "\x1b[21~".to_string(),
                    11 => "\x1b[23~".to_string(),
                    12 => "\x1b[24~".to_string(),
                    _ => return None,
                };
                sequence.into_bytes()
            }
            _ => return None,
        }
    };

    if alt && !control {
        bytes.insert(0, 0x1b);
    }

    Some(bytes)
}

fn spawn_input_thread(
    tx: mpsc::Sender<TerminalInput>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("myssh-terminal-input".into())
        .spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match event::poll(Duration::from_millis(50)) {
                    Ok(true) => match event::read() {
                        Ok(Event::Key(key)) => {
                            if let Some(bytes) = encode_key(key) {
                                if tx.blocking_send(TerminalInput::Data(bytes)).is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(Event::Paste(text)) => {
                            if tx
                                .blocking_send(TerminalInput::Data(text.into_bytes()))
                                .is_err()
                            {
                                break;
                            }
                        }
                        Ok(Event::Resize(columns, rows)) => {
                            if tx
                                .blocking_send(TerminalInput::Resize(rows, columns))
                                .is_err()
                            {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    },
                    Ok(false) => {}
                    Err(_) => break,
                }
            }
        })
        .expect("failed to spawn terminal input thread")
}

async fn send_outbound(
    tx: &mpsc::Sender<(MessageKind, Vec<u8>)>,
    kind: MessageKind,
    payload: Vec<u8>,
) -> io::Result<()> {
    tx.send((kind, payload))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Network writer stopped"))
}

fn spawn_network_writer(
    mut writer: myssh_core::ConnectionWriter,
    session_id: u128,
) -> (
    mpsc::Sender<(MessageKind, Vec<u8>)>,
    JoinHandle<io::Result<()>>,
) {
    let (tx, mut rx) = mpsc::channel(OUTPUT_QUEUE_CAPACITY);

    let task = tokio::spawn(async move {
        while let Some((kind, payload)) = rx.recv().await {
            writer.send(kind, session_id, payload).await?;
        }
        Ok(())
    });

    (tx, task)
}

/// Run an interactive remote shell over an already authenticated connection.
///
/// The caller is responsible for establishing the Transport and TLS session.
pub async fn run_shell(client: AuthenticatedClient) -> io::Result<()> {
    let mut connection = Connection::new(client.stream);

    let request_id = connection
        .send(
            MessageKind::SessionOpen,
            0,
            SessionOpenPayload {
                session_type: SessionType::Shell,
            }
            .encode(),
        )
        .await?;

    let response = connection.receive().await?;

    if response.header.kind != MessageKind::SessionOpened {
        return Err(invalid_data("Expected SessionOpened response"));
    }

    if response.header.request_id != request_id {
        return Err(invalid_data("SessionOpened request ID mismatch"));
    }

    let opened = SessionOpenedPayload::decode(&response.payload)?;

    if opened.status != SessionOpenStatus::Accepted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Host did not accept shell session: {:?}", opened.status),
        ));
    }

    let session_id = response.header.session_id;

    if session_id == 0 {
        return Err(invalid_data("Host returned an invalid session ID"));
    }

    let _raw_mode = RawModeGuard::enable()?;

    let (columns, rows) = terminal::size()?;
    let initial_size = SessionResizePayload {
        rows,
        columns,
        pixel_width: 0,
        pixel_height: 0,
    };

    let (mut reader, writer) = connection.into_split();
    let (outbound_tx, writer_task) = spawn_network_writer(writer, session_id);

    let (input_tx, mut input_rx) = mpsc::channel::<TerminalInput>(INPUT_QUEUE_CAPACITY);

    let stop_input = Arc::new(AtomicBool::new(false));
    let input_thread = spawn_input_thread(input_tx, stop_input.clone());

    let mut stdout = io::stdout();
    let mut remote_closed = false;

    let run_result: io::Result<()> = async {
        send_outbound(
            &outbound_tx,
            MessageKind::SessionResize,
            initial_size.encode()?,
        )
        .await?;

        loop {
            tokio::select! {
                incoming = reader.receive() => {
                    let frame = incoming?;

                    match frame.header.kind {
                        MessageKind::SessionData => {
                            if frame.header.session_id != session_id {
                                return Err(invalid_data("SessionData session ID mismatch"));
                            }

                            stdout.write_all(&frame.payload)?;
                            stdout.flush()?;
                        }

                        MessageKind::SessionClose => {
                            if frame.header.session_id != session_id {
                                return Err(invalid_data("SessionClose session ID mismatch"));
                            }

                            SessionClosePayload::decode(&frame.payload)?;
                            remote_closed = true;
                            break;
                        }

                        MessageKind::Ping => {
                            send_outbound(
                                &outbound_tx,
                                MessageKind::Pong,
                                frame.payload,
                            ).await?;
                        }

                        MessageKind::Error => {
                            return Err(invalid_data("Host reported a protocol error"));
                        }

                        _ => {
                            return Err(invalid_data("Unexpected message from Host"));
                        }
                    }
                }

                input = input_rx.recv() => {
                    match input {
                        Some(TerminalInput::Data(data)) => {
                            send_outbound(
                                &outbound_tx,
                                MessageKind::SessionData,
                                data,
                            ).await?;
                        }

                        Some(TerminalInput::Resize(rows, columns)) => {
                            let resize = SessionResizePayload {
                                rows,
                                columns,
                                pixel_width: 0,
                                pixel_height: 0,
                            };

                            send_outbound(
                                &outbound_tx,
                                MessageKind::SessionResize,
                                resize.encode()?,
                            ).await?;
                        }

                        None => break,
                    }
                }
            }
        }

        Ok(())
    }
    .await;

    stop_input.store(true, Ordering::Relaxed);
    drop(input_rx);

    let _ = input_thread.join();

    if !remote_closed {
        let _ = send_outbound(
            &outbound_tx,
            MessageKind::SessionClose,
            SessionClosePayload.encode(),
        )
        .await;
    }

    drop(outbound_tx);

    let writer_result = writer_task
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Network writer task panicked"))?;

    run_result?;
    writer_result?;

    Ok(())
}

#[cfg(test)]
mod terminal_tests {
    use super::*;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn encodes_plain_ascii_character() {
        assert_eq!(
            encode_key(key(KeyCode::Char('x'), KeyModifiers::NONE)),
            Some(vec![b'x']),
        );
    }

    #[test]
    fn encodes_unicode_character_as_utf8() {
        assert_eq!(
            encode_key(key(KeyCode::Char('中'), KeyModifiers::NONE)),
            Some("中".as_bytes().to_vec()),
        );
    }

    #[test]
    fn encodes_control_c_and_control_d() {
        assert_eq!(
            encode_key(key(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(vec![0x03]),
        );

        assert_eq!(
            encode_key(key(KeyCode::Char('d'), KeyModifiers::CONTROL)),
            Some(vec![0x04]),
        );
    }

    #[test]
    fn encodes_arrow_keys() {
        assert_eq!(
            encode_key(key(KeyCode::Up, KeyModifiers::NONE)),
            Some(b"\x1b[A".to_vec()),
        );

        assert_eq!(
            encode_key(key(KeyCode::Down, KeyModifiers::NONE)),
            Some(b"\x1b[B".to_vec()),
        );

        assert_eq!(
            encode_key(key(KeyCode::Left, KeyModifiers::NONE)),
            Some(b"\x1b[D".to_vec()),
        );

        assert_eq!(
            encode_key(key(KeyCode::Right, KeyModifiers::NONE)),
            Some(b"\x1b[C".to_vec()),
        );
    }

    #[test]
    fn encodes_enter_backspace_and_tab() {
        assert_eq!(
            encode_key(key(KeyCode::Enter, KeyModifiers::NONE)),
            Some(vec![b'\r']),
        );

        assert_eq!(
            encode_key(key(KeyCode::Backspace, KeyModifiers::NONE)),
            Some(vec![0x7f]),
        );

        assert_eq!(
            encode_key(key(KeyCode::Tab, KeyModifiers::NONE)),
            Some(vec![b'\t']),
        );
    }

    #[test]
    fn encodes_alt_character_with_escape_prefix() {
        assert_eq!(
            encode_key(key(KeyCode::Char('x'), KeyModifiers::ALT)),
            Some(b"\x1bx".to_vec()),
        );
    }
}
