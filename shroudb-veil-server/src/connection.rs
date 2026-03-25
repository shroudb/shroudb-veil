use std::sync::Arc;

use metrics::gauge;
use shroudb_veil_protocol::CommandDispatcher;
use shroudb_veil_protocol::command_parser::parse_command;
use shroudb_veil_protocol::serialize::response_to_json;
use shroudb_veil_protocol::transit_backend::TransitBackend;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::watch;

/// RAII guard that decrements the concurrent connections gauge on drop.
struct ConnectionGuard;

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        gauge!("veil_concurrent_connections").decrement(1.0);
    }
}

/// Handle a single client connection.
pub async fn handle_connection<T: TransitBackend + 'static>(
    stream: impl tokio::io::AsyncRead + AsyncWrite + Unpin + Send + 'static,
    dispatcher: Arc<CommandDispatcher<T>>,
    mut shutdown_rx: watch::Receiver<bool>,
    _rate_limit: Option<u32>,
) {
    gauge!("veil_concurrent_connections").increment(1.0);
    let _conn_guard = ConnectionGuard;

    let (reader_half, writer_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader_half);
    let mut writer = BufWriter::new(writer_half);

    loop {
        let mut line = String::new();
        let read_result = tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::debug!("connection shutting down by signal");
                    break;
                }
                continue;
            }
            result = reader.read_line(&mut line) => result,
        };

        match read_result {
            Ok(0) => {
                tracing::debug!("client disconnected (EOF)");
                break;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "read error");
                break;
            }
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let tokens = shell_split(line);

        let command = match parse_command(tokens) {
            Ok(cmd) => cmd,
            Err(e) => {
                let err_json = serde_json::json!({ "error": e.to_string() });
                let _ = write_response(&mut writer, &err_json).await;
                continue;
            }
        };

        let response = dispatcher.execute(command).await;
        let json = response_to_json(&response);
        if write_response(&mut writer, &json).await.is_err() {
            break;
        }
    }
}

async fn write_response(
    writer: &mut BufWriter<impl AsyncWrite + Unpin>,
    json: &serde_json::Value,
) -> Result<(), std::io::Error> {
    let mut output = serde_json::to_string(json)
        .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string());
    output.push('\n');
    writer.write_all(output.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// Split a command line into tokens, respecting double-quoted strings.
fn shell_split(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in input.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_split_basic() {
        let tokens = shell_split("CONTAINS messages QUERY dinner CIPHERTEXTS ct1 ct2");
        assert_eq!(
            tokens,
            &[
                "CONTAINS",
                "messages",
                "QUERY",
                "dinner",
                "CIPHERTEXTS",
                "ct1",
                "ct2"
            ]
        );
    }

    #[test]
    fn shell_split_quoted() {
        let tokens = shell_split(r#"FUZZY messages QUERY "grab dinner" CIPHERTEXTS ct1"#);
        assert_eq!(
            tokens,
            &[
                "FUZZY",
                "messages",
                "QUERY",
                "grab dinner",
                "CIPHERTEXTS",
                "ct1"
            ]
        );
    }

    #[test]
    fn shell_split_empty() {
        let tokens = shell_split("");
        assert!(tokens.is_empty());
    }
}
