use anyhow::Context;
use clap::Parser;
use shroudb_veil_client::VeilClient;

#[derive(Parser)]
#[command(name = "shroudb-veil-cli", about = "Veil CLI")]
struct Cli {
    /// Server address.
    #[arg(long, default_value = "127.0.0.1:6799", env = "VEIL_ADDR")]
    addr: String,

    /// Command to execute. If omitted, starts interactive mode.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let mut client = VeilClient::connect(&cli.addr)
        .await
        .with_context(|| format!("failed to connect to {}", cli.addr))?;

    if cli.command.is_empty() {
        interactive(&mut client).await
    } else {
        let args: Vec<&str> = cli.command.iter().map(|s| s.as_str()).collect();
        execute(&mut client, &args).await
    }
}

async fn execute(client: &mut VeilClient, args: &[&str]) -> anyhow::Result<()> {
    if args.is_empty() {
        anyhow::bail!("empty command");
    }

    match args[0].to_uppercase().as_str() {
        "HEALTH" => {
            client.health().await.context("health check failed")?;
            println!("OK");
        }
        "PING" => {
            println!("PONG");
        }
        "INDEX" if args.len() >= 2 => match args[1].to_uppercase().as_str() {
            "CREATE" if args.len() >= 3 => {
                let resp = client
                    .index_create(args[2])
                    .await
                    .context("index create failed")?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            "LIST" => {
                let names = client.index_list().await.context("index list failed")?;
                for name in names {
                    println!("{name}");
                }
            }
            "INFO" if args.len() >= 3 => {
                let info = client
                    .index_info(args[2])
                    .await
                    .context("index info failed")?;
                println!("{}", serde_json::to_string_pretty(&info)?);
            }
            _ => anyhow::bail!("usage: INDEX CREATE|LIST|INFO ..."),
        },
        "TOKENIZE" if args.len() >= 3 => {
            let field = find_option(args, "FIELD");
            let result = client
                .tokenize(args[1], args[2], field)
                .await
                .context("tokenize failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "words": result.words,
                    "trigrams": result.trigrams,
                    "tokens": result.tokens,
                }))?
            );
        }
        "PUT" if args.len() >= 4 => {
            let field = find_option(args, "FIELD");
            let blind = has_flag(args, "BLIND");
            let version = client
                .put(args[1], args[2], args[3], field, blind)
                .await
                .context("put failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "id": args[2],
                    "version": version,
                }))?
            );
        }
        "DELETE" if args.len() >= 3 => {
            client
                .delete(args[1], args[2])
                .await
                .context("delete failed")?;
            println!("OK");
        }
        "SEARCH" if args.len() >= 3 => {
            let mode = find_option(args, "MODE");
            let field = find_option(args, "FIELD");
            let limit = find_option(args, "LIMIT")
                .map(|l| l.parse::<usize>())
                .transpose()?;
            let blind = has_flag(args, "BLIND");
            let result = client
                .search(args[1], args[2], mode, field, limit, blind)
                .await
                .context("search failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "scanned": result.scanned,
                    "matched": result.matched,
                    "results": result.results.iter().map(|h| {
                        serde_json::json!({
                            "id": h.id,
                            "score": h.score,
                        })
                    }).collect::<Vec<_>>(),
                }))?
            );
        }
        _ => anyhow::bail!("unknown command: {}", args.join(" ")),
    }

    Ok(())
}

async fn interactive(client: &mut VeilClient) -> anyhow::Result<()> {
    use std::io::BufRead;

    let stdin = std::io::stdin();
    eprint!("veil> ");
    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            eprint!("veil> ");
            continue;
        }
        if line == "quit" || line == "exit" {
            break;
        }

        let args = shell_split(line);
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        match execute(client, &arg_refs).await {
            Ok(()) => {}
            Err(e) => eprintln!("error: {e}"),
        }
        eprint!("veil> ");
    }
    Ok(())
}

/// Split a command line by whitespace, preserving JSON objects in braces.
fn shell_split(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut brace_depth = 0;

    for ch in input.chars() {
        match ch {
            '{' | '[' => {
                brace_depth += 1;
                current.push(ch);
            }
            '}' | ']' => {
                brace_depth -= 1;
                current.push(ch);
            }
            ' ' | '\t' if brace_depth == 0 => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

fn find_option<'a>(args: &[&'a str], key: &str) -> Option<&'a str> {
    let upper = key.to_uppercase();
    args.windows(2)
        .find(|w| w[0].to_uppercase() == upper)
        .map(|w| w[1])
}

fn has_flag(args: &[&str], flag: &str) -> bool {
    let upper = flag.to_uppercase();
    args.iter().any(|a| a.to_uppercase() == upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_split_simple() {
        let args = shell_split("SEARCH users alice");
        assert_eq!(args, vec!["SEARCH", "users", "alice"]);
    }

    #[test]
    fn shell_split_with_options() {
        let args = shell_split("SEARCH users alice MODE exact LIMIT 10");
        assert_eq!(
            args,
            vec!["SEARCH", "users", "alice", "MODE", "exact", "LIMIT", "10"]
        );
    }
}
