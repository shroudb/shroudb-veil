use shroudb_acl::{AclRequirement, Scope};

/// Parsed Veil wire protocol command.
#[derive(Debug)]
pub enum VeilCommand {
    /// Authenticate this connection with a token.
    Auth {
        token: String,
    },

    // Index management
    IndexCreate {
        name: String,
    },
    IndexRotate {
        name: String,
    },
    IndexDestroy {
        name: String,
    },
    IndexReindex {
        name: String,
    },
    IndexReconcile {
        name: String,
        valid_ids: Vec<String>,
    },
    IndexList,
    IndexInfo {
        name: String,
    },

    // Token operations
    Tokenize {
        index: String,
        plaintext: String,
        field: Option<String>,
    },

    // Entry operations
    Put {
        index: String,
        id: String,
        data: String,
        field: Option<String>,
        /// When true, `data` is base64-encoded BlindTokenSet JSON (E2EE mode).
        /// When false, `data` is base64-encoded plaintext (standard mode).
        blind: bool,
    },
    Delete {
        index: String,
        id: String,
    },

    // Search
    Search {
        index: String,
        query: String,
        mode: String,
        field: Option<String>,
        limit: Option<usize>,
        /// When true, `query` is base64-encoded BlindTokenSet JSON (E2EE mode).
        /// When false, `query` is plain text (standard mode).
        blind: bool,
    },

    // Operational
    Health,
    Ping,
    CommandList,
}

impl VeilCommand {
    /// The ACL requirement for this command.
    pub fn acl_requirement(&self) -> AclRequirement {
        match self {
            // Pre-auth / public
            VeilCommand::Auth { .. }
            | VeilCommand::Health
            | VeilCommand::Ping
            | VeilCommand::CommandList => AclRequirement::None,

            // Listing index names is not sensitive
            VeilCommand::IndexList => AclRequirement::None,

            // Index creation, rotation, destruction, reindex, and reconcile are structural changes
            VeilCommand::IndexCreate { .. }
            | VeilCommand::IndexRotate { .. }
            | VeilCommand::IndexDestroy { .. }
            | VeilCommand::IndexReindex { .. }
            | VeilCommand::IndexReconcile { .. } => AclRequirement::Admin,

            // Read operations
            VeilCommand::Search { index, .. }
            | VeilCommand::IndexInfo { name: index }
            | VeilCommand::Tokenize { index, .. } => AclRequirement::Namespace {
                ns: format!("veil.{index}.*"),
                scope: Scope::Read,
                tenant_override: None,
            },

            // Write operations
            VeilCommand::Put { index, .. } | VeilCommand::Delete { index, .. } => {
                AclRequirement::Namespace {
                    ns: format!("veil.{index}.*"),
                    scope: Scope::Write,
                    tenant_override: None,
                }
            }
        }
    }
}

/// Parse raw RESP3 command arguments into a VeilCommand.
pub fn parse_command(args: &[&str]) -> Result<VeilCommand, String> {
    if args.is_empty() {
        return Err("empty command".into());
    }

    let cmd = args[0].to_uppercase();
    match cmd.as_str() {
        "AUTH" => {
            if args.len() < 2 {
                return Err("AUTH <token>".into());
            }
            Ok(VeilCommand::Auth {
                token: args[1].to_string(),
            })
        }
        "INDEX" => parse_index(args),
        "TOKENIZE" => parse_tokenize(args),
        "PUT" => parse_put(args),
        "DELETE" => parse_delete(args),
        "SEARCH" => parse_search(args),
        "HEALTH" => Ok(VeilCommand::Health),
        "PING" => Ok(VeilCommand::Ping),
        "COMMAND" => Ok(VeilCommand::CommandList),
        _ => Err(format!("unknown command: {}", args[0])),
    }
}

fn parse_index(args: &[&str]) -> Result<VeilCommand, String> {
    if args.len() < 2 {
        return Err("INDEX requires a subcommand".into());
    }
    match args[1].to_uppercase().as_str() {
        "CREATE" => {
            if args.len() < 3 {
                return Err("INDEX CREATE <name>".into());
            }
            Ok(VeilCommand::IndexCreate {
                name: args[2].to_string(),
            })
        }
        "ROTATE" => {
            if args.len() < 3 {
                return Err("INDEX ROTATE <name>".into());
            }
            Ok(VeilCommand::IndexRotate {
                name: args[2].to_string(),
            })
        }
        "DESTROY" => {
            if args.len() < 3 {
                return Err("INDEX DESTROY <name>".into());
            }
            Ok(VeilCommand::IndexDestroy {
                name: args[2].to_string(),
            })
        }
        "REINDEX" => {
            if args.len() < 3 {
                return Err("INDEX REINDEX <name>".into());
            }
            Ok(VeilCommand::IndexReindex {
                name: args[2].to_string(),
            })
        }
        "RECONCILE" => {
            if args.len() < 4 {
                return Err("INDEX RECONCILE <name> <id1> [id2 ...]".into());
            }
            let valid_ids = args[3..].iter().map(|s| s.to_string()).collect();
            Ok(VeilCommand::IndexReconcile {
                name: args[2].to_string(),
                valid_ids,
            })
        }
        "LIST" => Ok(VeilCommand::IndexList),
        "INFO" => {
            if args.len() < 3 {
                return Err("INDEX INFO <name>".into());
            }
            Ok(VeilCommand::IndexInfo {
                name: args[2].to_string(),
            })
        }
        sub => Err(format!("unknown INDEX subcommand: {sub}")),
    }
}

fn parse_tokenize(args: &[&str]) -> Result<VeilCommand, String> {
    if args.len() < 3 {
        return Err("TOKENIZE <index> <plaintext_b64> [FIELD <name>]".into());
    }
    let field = find_option(args, "FIELD").map(String::from);
    Ok(VeilCommand::Tokenize {
        index: args[1].to_string(),
        plaintext: args[2].to_string(),
        field,
    })
}

fn parse_put(args: &[&str]) -> Result<VeilCommand, String> {
    if args.len() < 4 {
        return Err("PUT <index> <id> <data_b64> [FIELD <name>] [BLIND]".into());
    }
    let field = find_option(args, "FIELD").map(String::from);
    let blind = has_flag(args, "BLIND");
    Ok(VeilCommand::Put {
        index: args[1].to_string(),
        id: args[2].to_string(),
        data: args[3].to_string(),
        field,
        blind,
    })
}

fn parse_delete(args: &[&str]) -> Result<VeilCommand, String> {
    if args.len() < 3 {
        return Err("DELETE <index> <id>".into());
    }
    Ok(VeilCommand::Delete {
        index: args[1].to_string(),
        id: args[2].to_string(),
    })
}

fn parse_search(args: &[&str]) -> Result<VeilCommand, String> {
    if args.len() < 3 {
        return Err(
            "SEARCH <index> <query> [MODE exact|contains|prefix|fuzzy] [FIELD <name>] [LIMIT <n>] [BLIND]"
                .into(),
        );
    }
    let mode = find_option(args, "MODE").unwrap_or("contains").to_string();
    let field = find_option(args, "FIELD").map(String::from);
    let limit = find_option(args, "LIMIT")
        .map(|v| v.parse::<usize>())
        .transpose()
        .map_err(|e| format!("invalid LIMIT: {e}"))?;
    let blind = has_flag(args, "BLIND");

    Ok(VeilCommand::Search {
        index: args[1].to_string(),
        query: args[2].to_string(),
        mode,
        field,
        limit,
        blind,
    })
}

/// Find an optional keyword argument: `KEY value` in the args list.
fn find_option<'a>(args: &[&'a str], key: &str) -> Option<&'a str> {
    let upper = key.to_uppercase();
    args.windows(2)
        .find(|w| w[0].to_uppercase() == upper)
        .map(|w| w[1])
}

/// Check for a standalone flag keyword (no value) in the args list.
fn has_flag(args: &[&str], flag: &str) -> bool {
    let upper = flag.to_uppercase();
    args.iter().any(|a| a.to_uppercase() == upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_index_create() {
        let cmd = parse_command(&["INDEX", "CREATE", "users"]).unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::IndexCreate { name } if name == "users"
        ));
    }

    #[test]
    fn parse_index_list() {
        let cmd = parse_command(&["INDEX", "LIST"]).unwrap();
        assert!(matches!(cmd, VeilCommand::IndexList));
    }

    #[test]
    fn parse_index_info() {
        let cmd = parse_command(&["INDEX", "INFO", "users"]).unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::IndexInfo { name } if name == "users"
        ));
    }

    #[test]
    fn parse_tokenize() {
        let cmd = parse_command(&["TOKENIZE", "users", "SGVsbG8="]).unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::Tokenize { index, plaintext, field: None }
            if index == "users" && plaintext == "SGVsbG8="
        ));
    }

    #[test]
    fn parse_tokenize_with_field() {
        let cmd = parse_command(&["TOKENIZE", "users", "SGVsbG8=", "FIELD", "name"]).unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::Tokenize { field: Some(f), .. } if f == "name"
        ));
    }

    #[test]
    fn parse_put() {
        let cmd = parse_command(&["PUT", "users", "u1", "SGVsbG8="]).unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::Put { index, id, data, field: None, blind: false }
            if index == "users" && id == "u1" && data == "SGVsbG8="
        ));
    }

    #[test]
    fn parse_put_with_field() {
        let cmd = parse_command(&["PUT", "users", "u1", "SGVsbG8=", "FIELD", "name"]).unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::Put { field: Some(f), blind: false, .. } if f == "name"
        ));
    }

    #[test]
    fn parse_put_blind() {
        let cmd = parse_command(&["PUT", "msgs", "m1", "dG9rZW5z", "BLIND"]).unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::Put { index, id, data, blind: true, .. }
            if index == "msgs" && id == "m1" && data == "dG9rZW5z"
        ));
    }

    #[test]
    fn parse_put_blind_with_field() {
        let cmd =
            parse_command(&["PUT", "msgs", "m1", "dG9rZW5z", "FIELD", "name", "BLIND"]).unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::Put { blind: true, field: Some(f), .. } if f == "name"
        ));
    }

    #[test]
    fn parse_delete() {
        let cmd = parse_command(&["DELETE", "users", "u1"]).unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::Delete { index, id }
            if index == "users" && id == "u1"
        ));
    }

    #[test]
    fn parse_search_default_mode() {
        let cmd = parse_command(&["SEARCH", "users", "alice"]).unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::Search { index, query, mode, field: None, limit: None, blind: false }
            if index == "users" && query == "alice" && mode == "contains"
        ));
    }

    #[test]
    fn parse_search_with_options() {
        let cmd = parse_command(&[
            "SEARCH", "users", "alice", "MODE", "exact", "FIELD", "name", "LIMIT", "10",
        ])
        .unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::Search {
                mode,
                field: Some(f),
                limit: Some(10),
                blind: false,
                ..
            } if mode == "exact" && f == "name"
        ));
    }

    #[test]
    fn parse_search_blind() {
        let cmd = parse_command(&["SEARCH", "msgs", "dG9rZW5z", "MODE", "exact", "BLIND"]).unwrap();
        assert!(matches!(cmd, VeilCommand::Search { blind: true, .. }));
    }

    #[test]
    fn parse_search_blind_with_limit() {
        let cmd = parse_command(&[
            "SEARCH", "msgs", "dG9rZW5z", "MODE", "exact", "LIMIT", "5", "BLIND",
        ])
        .unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::Search {
                blind: true,
                limit: Some(5),
                ..
            }
        ));
    }

    #[test]
    fn parse_health() {
        let cmd = parse_command(&["HEALTH"]).unwrap();
        assert!(matches!(cmd, VeilCommand::Health));
    }

    #[test]
    fn parse_ping() {
        let cmd = parse_command(&["PING"]).unwrap();
        assert!(matches!(cmd, VeilCommand::Ping));
    }

    #[test]
    fn parse_index_reindex() {
        let cmd = parse_command(&["INDEX", "REINDEX", "users"]).unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::IndexReindex { name } if name == "users"
        ));
    }

    #[test]
    fn parse_index_reindex_missing_name() {
        assert!(parse_command(&["INDEX", "REINDEX"]).is_err());
    }

    #[test]
    fn parse_index_reconcile() {
        let cmd = parse_command(&["INDEX", "RECONCILE", "users", "id1", "id2", "id3"]).unwrap();
        match cmd {
            VeilCommand::IndexReconcile { name, valid_ids } => {
                assert_eq!(name, "users");
                assert_eq!(valid_ids, vec!["id1", "id2", "id3"]);
            }
            _ => panic!("expected IndexReconcile"),
        }
    }

    #[test]
    fn parse_index_reconcile_missing_ids() {
        assert!(parse_command(&["INDEX", "RECONCILE", "users"]).is_err());
    }

    #[test]
    fn parse_index_rotate() {
        let cmd = parse_command(&["INDEX", "ROTATE", "users"]).unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::IndexRotate { name } if name == "users"
        ));
    }

    #[test]
    fn parse_index_destroy() {
        let cmd = parse_command(&["INDEX", "DESTROY", "users"]).unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::IndexDestroy { name } if name == "users"
        ));
    }

    #[test]
    fn unknown_command_errors() {
        assert!(parse_command(&["NOPE"]).is_err());
    }

    #[test]
    fn empty_command_errors() {
        assert!(parse_command(&[]).is_err());
    }
}
