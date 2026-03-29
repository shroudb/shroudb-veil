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
        plaintext: String,
        field: Option<String>,
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

            // Index creation is a structural change
            VeilCommand::IndexCreate { .. } => AclRequirement::Admin,

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
        return Err("PUT <index> <id> <plaintext_b64> [FIELD <name>]".into());
    }
    let field = find_option(args, "FIELD").map(String::from);
    Ok(VeilCommand::Put {
        index: args[1].to_string(),
        id: args[2].to_string(),
        plaintext: args[3].to_string(),
        field,
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
            "SEARCH <index> <query> [MODE exact|contains|prefix|fuzzy] [FIELD <name>] [LIMIT <n>]"
                .into(),
        );
    }
    let mode = find_option(args, "MODE").unwrap_or("contains").to_string();
    let field = find_option(args, "FIELD").map(String::from);
    let limit = find_option(args, "LIMIT")
        .map(|v| v.parse::<usize>())
        .transpose()
        .map_err(|e| format!("invalid LIMIT: {e}"))?;

    Ok(VeilCommand::Search {
        index: args[1].to_string(),
        query: args[2].to_string(),
        mode,
        field,
        limit,
    })
}

/// Find an optional keyword argument: `KEY value` in the args list.
fn find_option<'a>(args: &[&'a str], key: &str) -> Option<&'a str> {
    let upper = key.to_uppercase();
    args.windows(2)
        .find(|w| w[0].to_uppercase() == upper)
        .map(|w| w[1])
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
            VeilCommand::Put { index, id, plaintext, field: None }
            if index == "users" && id == "u1" && plaintext == "SGVsbG8="
        ));
    }

    #[test]
    fn parse_put_with_field() {
        let cmd = parse_command(&["PUT", "users", "u1", "SGVsbG8=", "FIELD", "name"]).unwrap();
        assert!(matches!(
            cmd,
            VeilCommand::Put { field: Some(f), .. } if f == "name"
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
            VeilCommand::Search { index, query, mode, field: None, limit: None }
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
                ..
            } if mode == "exact" && f == "name"
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
    fn unknown_command_errors() {
        assert!(parse_command(&["NOPE"]).is_err());
    }

    #[test]
    fn empty_command_errors() {
        assert!(parse_command(&[]).is_err());
    }
}
