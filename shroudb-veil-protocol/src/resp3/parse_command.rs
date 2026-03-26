//! Parse a RESP3 frame (array of bulk strings) into a Veil `Command`.
//!
//! This is a thin wrapper around `command_parser::parse_command` — it extracts
//! string arguments from the RESP3 frame and delegates to the existing parser.

use shroudb_protocol_wire::Resp3Frame;

use crate::command::Command;
use crate::error::CommandError;

/// Parse a RESP3 frame into a Veil command.
///
/// The frame must be an array of bulk strings (standard RESP3 command format).
pub fn parse_command(frame: Resp3Frame) -> Result<Command, CommandError> {
    let args = extract_args(frame)?;
    crate::command_parser::parse_command(args)
}

fn extract_args(frame: Resp3Frame) -> Result<Vec<String>, CommandError> {
    match frame {
        Resp3Frame::Array(items) => {
            let mut args = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Resp3Frame::BulkString(data) => {
                        args.push(String::from_utf8(data).map_err(|e| CommandError::BadArg {
                            message: format!("invalid UTF-8 in argument: {e}"),
                        })?);
                    }
                    Resp3Frame::SimpleString(s) => {
                        args.push(s);
                    }
                    _ => {
                        return Err(CommandError::BadArg {
                            message: "expected bulk string in command array".into(),
                        });
                    }
                }
            }
            Ok(args)
        }
        _ => Err(CommandError::BadArg {
            message: "expected array frame for command".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bulk(s: &str) -> Resp3Frame {
        Resp3Frame::BulkString(s.as_bytes().to_vec())
    }

    fn cmd(parts: &[&str]) -> Resp3Frame {
        Resp3Frame::Array(parts.iter().map(|s| bulk(s)).collect())
    }

    #[test]
    fn parse_health() {
        let c = parse_command(cmd(&["HEALTH"])).unwrap();
        assert!(matches!(c, Command::Health));
    }

    #[test]
    fn parse_auth() {
        let c = parse_command(cmd(&["AUTH", "token123"])).unwrap();
        match c {
            Command::Auth { token } => assert_eq!(token, "token123"),
            _ => panic!("expected Auth"),
        }
    }

    #[test]
    fn parse_fuzzy_search() {
        let c = parse_command(cmd(&[
            "FUZZY",
            "messages",
            "QUERY",
            "dinnr",
            "CIPHERTEXTS",
            "v1:gcm:abc",
        ]))
        .unwrap();
        assert!(matches!(c, Command::Fuzzy(_)));
    }

    #[test]
    fn parse_index() {
        let c = parse_command(cmd(&[
            "INDEX", "messages", "aGVsbG8=", "FIELD", "body", "CONTEXT", "chan-42",
        ]))
        .unwrap();
        match c {
            Command::Index(a) => {
                assert_eq!(a.keyring, "messages");
                assert_eq!(a.plaintext_b64, "aGVsbG8=");
                assert_eq!(a.field.as_deref(), Some("body"));
                assert_eq!(a.context.as_deref(), Some("chan-42"));
            }
            _ => panic!("expected Index"),
        }
    }

    #[test]
    fn reject_non_array_frame() {
        let err = parse_command(Resp3Frame::SimpleString("HEALTH".into()));
        assert!(err.is_err());
    }

    #[test]
    fn reject_empty_array() {
        let err = parse_command(Resp3Frame::Array(vec![]));
        assert!(err.is_err());
    }
}
