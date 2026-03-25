//! Parse a list of string tokens into a Veil `Command`.

use crate::command::{Command, IndexArgs, SearchArgs, SearchEntry};
use crate::error::CommandError;

pub fn parse_command(strings: Vec<String>) -> Result<Command, CommandError> {
    if strings.is_empty() {
        return Err(CommandError::BadArg {
            message: "empty command".into(),
        });
    }

    let verb = strings[0].to_ascii_uppercase();
    let args = &strings[1..];

    match verb.as_str() {
        "FUZZY" => parse_search_args(args).map(Command::Fuzzy),
        "CONTAINS" => parse_search_args(args).map(Command::Contains),
        "EXACT" => parse_search_args(args).map(Command::Exact),
        "PREFIX" => parse_search_args(args).map(Command::Prefix),
        "INDEX" => parse_index_args(args).map(Command::Index),
        "HEALTH" => Ok(Command::Health),
        "AUTH" => parse_auth(args),
        "PIPELINE" => parse_pipeline(&strings),
        _ => Err(CommandError::BadArg {
            message: format!("unknown command: {verb}"),
        }),
    }
}

fn require_arg<'a>(args: &'a [String], index: usize, name: &str) -> Result<&'a str, CommandError> {
    args.get(index)
        .map(|s| s.as_str())
        .ok_or_else(|| CommandError::BadArg {
            message: format!("missing required argument: {name}"),
        })
}

fn find_opt<'a>(args: &'a [String], keyword: &str) -> Option<&'a str> {
    args.windows(2).find_map(|w| {
        if w[0].eq_ignore_ascii_case(keyword) {
            Some(w[1].as_str())
        } else {
            None
        }
    })
}

// <keyring> QUERY <query> [FIELD <f>] [CONTEXT <aad>] [LIMIT <n>] [REWRAP] CIPHERTEXTS <ct1> ...
// or: ... ENTRIES <b64_json>
fn parse_search_args(args: &[String]) -> Result<SearchArgs, CommandError> {
    let keyring = require_arg(args, 0, "keyring")?.to_owned();
    let rest = &args[1..];

    let query = find_opt(rest, "QUERY")
        .ok_or_else(|| CommandError::BadArg {
            message: "missing QUERY keyword".into(),
        })?
        .to_owned();

    let field = find_opt(rest, "FIELD").map(|s| s.to_owned());
    let context = find_opt(rest, "CONTEXT").map(|s| s.to_owned());
    let limit = find_opt(rest, "LIMIT")
        .map(|s| {
            s.parse::<usize>().map_err(|e| CommandError::BadArg {
                message: format!("invalid LIMIT: {e}"),
            })
        })
        .transpose()?;
    let rewrap = rest.iter().any(|s| s.eq_ignore_ascii_case("REWRAP"));

    // Check for ENTRIES (JSON with tokens) or CIPHERTEXTS (flat list).
    let entries =
        if let Some(entries_pos) = rest.iter().position(|s| s.eq_ignore_ascii_case("ENTRIES")) {
            let b64 = require_arg(rest, entries_pos + 1, "ENTRIES value")?;
            parse_entries_json(b64)?
        } else {
            let ct_start = rest
                .iter()
                .position(|s| s.eq_ignore_ascii_case("CIPHERTEXTS"))
                .ok_or_else(|| CommandError::BadArg {
                    message: "missing CIPHERTEXTS or ENTRIES keyword".into(),
                })?;

            let ciphertexts: Vec<String> = rest[ct_start + 1..].to_vec();
            if ciphertexts.is_empty() {
                return Err(CommandError::BadArg {
                    message: "CIPHERTEXTS requires at least one ciphertext".into(),
                });
            }

            ciphertexts
                .into_iter()
                .map(|ct| SearchEntry {
                    ciphertext: ct,
                    tokens: None,
                })
                .collect()
        };

    if entries.is_empty() {
        return Err(CommandError::BadArg {
            message: "at least one entry required".into(),
        });
    }

    Ok(SearchArgs {
        keyring,
        query,
        field,
        context,
        limit,
        rewrap,
        entries,
    })
}

/// Parse base64-encoded JSON entries with optional tokens.
///
/// Expected JSON shape: `[{"ct":"v1:gcm:...","tokens":["v1:gcm:t1",...]}, ...]`
fn parse_entries_json(b64: &str) -> Result<Vec<SearchEntry>, CommandError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| CommandError::BadArg {
            message: format!("invalid base64 in ENTRIES: {e}"),
        })?;
    let json: Vec<serde_json::Value> =
        serde_json::from_slice(&bytes).map_err(|e| CommandError::BadArg {
            message: format!("invalid JSON in ENTRIES: {e}"),
        })?;

    json.into_iter()
        .map(|obj| {
            let ct = obj
                .get("ct")
                .and_then(|v| v.as_str())
                .ok_or_else(|| CommandError::BadArg {
                    message: "ENTRIES item missing 'ct' field".into(),
                })?
                .to_string();
            let tokens = obj.get("tokens").and_then(|v| {
                v.as_array().map(|arr| {
                    arr.iter()
                        .filter_map(|t| t.as_str().map(|s| s.to_string()))
                        .collect()
                })
            });
            Ok(SearchEntry {
                ciphertext: ct,
                tokens,
            })
        })
        .collect()
}

// INDEX <keyring> <b64_plaintext> [FIELD <f>] [CONTEXT <aad>]
fn parse_index_args(args: &[String]) -> Result<IndexArgs, CommandError> {
    let keyring = require_arg(args, 0, "keyring")?.to_owned();
    let plaintext_b64 = require_arg(args, 1, "plaintext")?.to_owned();
    let rest = &args[2..];
    let field = find_opt(rest, "FIELD").map(|s| s.to_owned());
    let context = find_opt(rest, "CONTEXT").map(|s| s.to_owned());
    Ok(IndexArgs {
        keyring,
        plaintext_b64,
        field,
        context,
    })
}

fn parse_auth(args: &[String]) -> Result<Command, CommandError> {
    let token = require_arg(args, 0, "token")?.to_owned();
    Ok(Command::Auth { token })
}

fn parse_pipeline(all_strings: &[String]) -> Result<Command, CommandError> {
    let end_idx = all_strings
        .iter()
        .position(|s| s.eq_ignore_ascii_case("END"))
        .ok_or_else(|| CommandError::BadArg {
            message: "PIPELINE without END".into(),
        })?;

    let inner = &all_strings[1..end_idx];
    if inner.is_empty() {
        return Ok(Command::Pipeline(vec![]));
    }

    let verbs = [
        "FUZZY", "CONTAINS", "EXACT", "PREFIX", "INDEX", "HEALTH", "AUTH",
    ];

    let mut commands = Vec::new();
    let mut start = 0;

    for i in 1..=inner.len() {
        let is_boundary =
            i == inner.len() || verbs.contains(&inner[i].to_ascii_uppercase().as_str());
        if is_boundary {
            let slice = &inner[start..i];
            if !slice.is_empty() {
                commands.push(parse_command(slice.to_vec())?);
            }
            start = i;
        }
    }

    Ok(Command::Pipeline(commands))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_health() {
        let cmd = parse_command(args(&["HEALTH"])).unwrap();
        assert!(matches!(cmd, Command::Health));
    }

    #[test]
    fn parse_auth_cmd() {
        let cmd = parse_command(args(&["AUTH", "secret123"])).unwrap();
        match cmd {
            Command::Auth { token } => assert_eq!(token, "secret123"),
            _ => panic!("expected Auth"),
        }
    }

    #[test]
    fn parse_contains() {
        let cmd = parse_command(args(&[
            "CONTAINS",
            "messages",
            "QUERY",
            "dinner",
            "FIELD",
            "body",
            "LIMIT",
            "50",
            "CIPHERTEXTS",
            "v1:gcm:abc123",
            "v1:gcm:def456",
        ]))
        .unwrap();
        match cmd {
            Command::Contains(a) => {
                assert_eq!(a.keyring, "messages");
                assert_eq!(a.query, "dinner");
                assert_eq!(a.field.as_deref(), Some("body"));
                assert_eq!(a.limit, Some(50));
                assert!(!a.rewrap);
                assert_eq!(a.entries.len(), 2);
            }
            _ => panic!("expected Contains"),
        }
    }

    #[test]
    fn parse_contains_with_rewrap() {
        let cmd = parse_command(args(&[
            "CONTAINS",
            "messages",
            "QUERY",
            "dinner",
            "REWRAP",
            "CIPHERTEXTS",
            "v1:gcm:abc",
        ]))
        .unwrap();
        match cmd {
            Command::Contains(a) => {
                assert!(a.rewrap);
            }
            _ => panic!("expected Contains"),
        }
    }

    #[test]
    fn parse_fuzzy() {
        let cmd = parse_command(args(&[
            "FUZZY",
            "messages",
            "QUERY",
            "dinnr",
            "CIPHERTEXTS",
            "v1:gcm:abc",
        ]))
        .unwrap();
        assert!(matches!(cmd, Command::Fuzzy(_)));
    }

    #[test]
    fn parse_exact() {
        let cmd = parse_command(args(&[
            "EXACT",
            "messages",
            "QUERY",
            "hello",
            "CIPHERTEXTS",
            "v1:gcm:abc",
        ]))
        .unwrap();
        assert!(matches!(cmd, Command::Exact(_)));
    }

    #[test]
    fn parse_prefix() {
        let cmd = parse_command(args(&[
            "PREFIX",
            "messages",
            "QUERY",
            "din",
            "CIPHERTEXTS",
            "v1:gcm:abc",
        ]))
        .unwrap();
        assert!(matches!(cmd, Command::Prefix(_)));
    }

    #[test]
    fn parse_index() {
        let cmd = parse_command(args(&[
            "INDEX", "messages", "aGVsbG8=", "FIELD", "body", "CONTEXT", "chan-42",
        ]))
        .unwrap();
        match cmd {
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
    fn parse_missing_query() {
        let err = parse_command(args(&["CONTAINS", "messages", "CIPHERTEXTS", "ct1"]));
        assert!(err.is_err());
    }

    #[test]
    fn parse_missing_ciphertexts() {
        let err = parse_command(args(&["CONTAINS", "messages", "QUERY", "dinner"]));
        assert!(err.is_err());
    }

    #[test]
    fn parse_unknown_command() {
        let err = parse_command(args(&["BOGUS", "arg"]));
        assert!(err.is_err());
    }

    #[test]
    fn parse_entries_json_format() {
        use base64::Engine;
        let json = serde_json::json!([
            {"ct": "v1:gcm:abc", "tokens": ["v1:gcm:t1", "v1:gcm:t2"]},
            {"ct": "v1:gcm:def"}
        ]);
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&json).unwrap());
        let cmd = parse_command(args(&[
            "CONTAINS", "messages", "QUERY", "dinner", "ENTRIES", &b64,
        ]))
        .unwrap();
        match cmd {
            Command::Contains(a) => {
                assert_eq!(a.entries.len(), 2);
                assert_eq!(a.entries[0].ciphertext, "v1:gcm:abc");
                assert_eq!(
                    a.entries[0].tokens.as_deref(),
                    Some(&["v1:gcm:t1".to_string(), "v1:gcm:t2".to_string()][..])
                );
                assert!(a.entries[1].tokens.is_none());
            }
            _ => panic!("expected Contains"),
        }
    }
}
