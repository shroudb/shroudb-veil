//! ShrouDB Veil CLI — interactive command-line client for encrypted search.

use anyhow::Result;
use clap::Parser;
use shroudb_veil_client::VeilClient;

#[derive(Parser)]
#[command(
    name = "shroudb-veil-cli",
    about = "Interactive CLI for ShrouDB Veil (encrypted search)",
    version
)]
struct Cli {
    /// Veil server address (host:port).
    #[arg(short, long, default_value = "127.0.0.1:6599")]
    addr: String,

    /// Connection URI (overrides --addr).
    #[arg(long)]
    uri: Option<String>,

    /// Output as JSON.
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let addr = if let Some(ref uri) = cli.uri {
        let (addr, _token) = shroudb_veil_client::parse_uri(uri)?;
        addr
    } else {
        cli.addr.clone()
    };

    let mut client = VeilClient::connect(&addr).await?;

    println!("Connected to ShrouDB Veil at {addr}");
    println!("Commands: FUZZY, CONTAINS, EXACT, PREFIX, INDEX, HEALTH, quit");
    println!("Example: CONTAINS messages QUERY \"dinner\" CIPHERTEXTS ct1 ct2\n");

    let mut rl = rustyline::DefaultEditor::new()?;

    loop {
        let line = match rl.readline("veil> ") {
            Ok(line) => line,
            Err(
                rustyline::error::ReadlineError::Interrupted | rustyline::error::ReadlineError::Eof,
            ) => break,
            Err(e) => {
                eprintln!("readline error: {e}");
                break;
            }
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let _ = rl.add_history_entry(line);

        match line.to_ascii_lowercase().as_str() {
            "quit" | "exit" => break,
            "help" => {
                print_help();
                continue;
            }
            _ => {}
        }

        if let Err(e) = dispatch_command(&mut client, line, cli.json).await {
            eprintln!("error: {e}");
        }
    }

    println!("Goodbye.");
    Ok(())
}

async fn dispatch_command(client: &mut VeilClient, line: &str, json: bool) -> Result<()> {
    let tokens = shell_split(line);
    if tokens.is_empty() {
        return Ok(());
    }

    let verb = tokens[0].to_ascii_uppercase();

    match verb.as_str() {
        "HEALTH" => {
            let h = client.health().await?;
            if json {
                let j = serde_json::json!({
                    "state": h.state,
                    "transit": h.transit,
                });
                println!("{}", serde_json::to_string_pretty(&j)?);
            } else {
                println!("state: {}", h.state);
                if let Some(t) = &h.transit {
                    println!("transit: {t}");
                }
            }
        }
        "FUZZY" | "CONTAINS" | "EXACT" | "PREFIX" => {
            let args = parse_search_tokens(&tokens[1..])?;
            let result = match verb.as_str() {
                "FUZZY" => {
                    client
                        .fuzzy(
                            &args.keyring,
                            &args.query,
                            args.field.as_deref(),
                            args.context.as_deref(),
                            args.limit,
                            &args
                                .ciphertexts
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>(),
                        )
                        .await?
                }
                "CONTAINS" => {
                    client
                        .contains(
                            &args.keyring,
                            &args.query,
                            args.field.as_deref(),
                            args.context.as_deref(),
                            args.limit,
                            &args
                                .ciphertexts
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>(),
                        )
                        .await?
                }
                "EXACT" => {
                    client
                        .exact(
                            &args.keyring,
                            &args.query,
                            args.field.as_deref(),
                            args.context.as_deref(),
                            args.limit,
                            &args
                                .ciphertexts
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>(),
                        )
                        .await?
                }
                "PREFIX" => {
                    client
                        .prefix(
                            &args.keyring,
                            &args.query,
                            args.field.as_deref(),
                            args.context.as_deref(),
                            args.limit,
                            &args
                                .ciphertexts
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>(),
                        )
                        .await?
                }
                _ => unreachable!(),
            };

            if json {
                let j = serde_json::json!({
                    "scanned": result.scanned,
                    "matched": result.matched,
                    "filtered": result.filtered,
                    "results": result.results.iter().map(|r| {
                        let mut entry = serde_json::json!({
                            "id": r.id,
                            "score": r.score,
                        });
                        if let Some(ref ct) = r.ciphertext {
                            entry["ciphertext"] = serde_json::json!(ct);
                        }
                        if let Some(kv) = r.key_version {
                            entry["key_version"] = serde_json::json!(kv);
                        }
                        entry
                    }).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&j)?);
            } else {
                println!(
                    "scanned: {}, matched: {}, filtered: {}, returned: {}",
                    result.scanned,
                    result.matched,
                    result.filtered,
                    result.results.len()
                );
                for r in &result.results {
                    println!("  id={} score={:.3}", r.id, r.score);
                }
            }
        }
        "INDEX" => {
            if tokens.len() < 3 {
                anyhow::bail!(
                    "INDEX requires: INDEX <keyring> <b64_plaintext> [FIELD <f>] [CONTEXT <aad>]"
                );
            }
            let keyring = &tokens[1];
            let plaintext_b64 = &tokens[2];
            let rest = &tokens[3..];
            let field = find_opt(rest, "FIELD");
            let context = find_opt(rest, "CONTEXT");

            let result = client.index(keyring, plaintext_b64, field, context).await?;

            if json {
                let j = serde_json::json!({
                    "ciphertext": result.ciphertext,
                    "key_version": result.key_version,
                    "tokens": result.tokens,
                });
                println!("{}", serde_json::to_string_pretty(&j)?);
            } else {
                println!("ciphertext: {}", result.ciphertext);
                println!("key_version: {}", result.key_version);
                println!("tokens: {} generated", result.tokens.len());
            }
        }
        _ => {
            eprintln!("unknown command: {verb}. Type 'help' for usage.");
        }
    }

    Ok(())
}

struct SearchTokens {
    keyring: String,
    query: String,
    field: Option<String>,
    context: Option<String>,
    limit: Option<usize>,
    ciphertexts: Vec<String>,
}

fn parse_search_tokens(tokens: &[String]) -> Result<SearchTokens> {
    if tokens.is_empty() {
        anyhow::bail!("missing keyring argument");
    }

    let keyring = tokens[0].clone();
    let rest = &tokens[1..];

    let query = find_opt(rest, "QUERY")
        .ok_or_else(|| anyhow::anyhow!("missing QUERY keyword"))?
        .to_string();

    let field = find_opt(rest, "FIELD").map(|s| s.to_string());
    let context = find_opt(rest, "CONTEXT").map(|s| s.to_string());
    let limit = find_opt(rest, "LIMIT")
        .map(|s| s.parse::<usize>())
        .transpose()?;

    let ct_start = rest
        .iter()
        .position(|s| s.eq_ignore_ascii_case("CIPHERTEXTS"))
        .ok_or_else(|| anyhow::anyhow!("missing CIPHERTEXTS keyword"))?;

    let ciphertexts: Vec<String> = rest[ct_start + 1..].to_vec();
    if ciphertexts.is_empty() {
        anyhow::bail!("CIPHERTEXTS requires at least one ciphertext");
    }

    Ok(SearchTokens {
        keyring,
        query,
        field,
        context,
        limit,
        ciphertexts,
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

fn shell_split(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in input.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn print_help() {
    println!("Commands:");
    println!(
        "  HEALTH                                              — Check server + Transit health"
    );
    println!("  FUZZY <keyring> QUERY <q> CIPHERTEXTS <ct> ...      — Fuzzy search");
    println!("  CONTAINS <keyring> QUERY <q> CIPHERTEXTS <ct> ...   — Substring search");
    println!("  EXACT <keyring> QUERY <q> CIPHERTEXTS <ct> ...      — Exact match");
    println!("  PREFIX <keyring> QUERY <q> CIPHERTEXTS <ct> ...     — Prefix match");
    println!("    Options: [FIELD <f>] [CONTEXT <aad>] [LIMIT <n>] [REWRAP]");
    println!("  INDEX <keyring> <b64_plaintext> [FIELD <f>] [CONTEXT <aad>]");
    println!("                                                      — Encrypt + generate tokens");
    println!("  quit                                                — Exit");
}
