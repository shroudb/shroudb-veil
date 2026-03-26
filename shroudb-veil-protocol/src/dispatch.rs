use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use metrics::{counter, histogram};
use shroudb_veil_core::MatchMode;

use crate::command::{Command, command_verb};
use crate::error::CommandError;
use crate::handlers;
use crate::response::{CommandResponse, ResponseMap, ResponseValue};
use crate::search_engine::SearchConfig;
use crate::transit_backend::TransitBackend;

/// Routes parsed Veil commands to the appropriate handler.
pub struct CommandDispatcher<T: TransitBackend> {
    transit: Arc<T>,
    search_config: SearchConfig,
    /// In-memory config store for stateless engines (no WAL persistence).
    config: DashMap<String, String>,
}

impl<T: TransitBackend + 'static> CommandDispatcher<T> {
    pub fn new(transit: Arc<T>, search_config: SearchConfig) -> Self {
        let config = DashMap::new();
        config.insert(
            "search.max_batch_size".into(),
            search_config.max_batch_size.to_string(),
        );
        config.insert(
            "search.default_result_limit".into(),
            search_config.default_result_limit.to_string(),
        );
        config.insert(
            "search.decrypt_batch_size".into(),
            search_config.decrypt_batch_size.to_string(),
        );
        Self {
            transit,
            search_config,
            config,
        }
    }

    pub async fn execute(&self, cmd: Command) -> CommandResponse {
        // Handle pipeline recursively.
        if let Command::Pipeline(commands) = cmd {
            let mut results = Vec::with_capacity(commands.len());
            for c in commands {
                results.push(Box::pin(self.execute(c)).await);
            }
            return CommandResponse::Array(results);
        }

        let verb = command_verb(&cmd);
        let keyring_label = cmd.keyring().unwrap_or("_global").to_string();

        let start = Instant::now();
        let result = self.dispatch(cmd).await;
        let duration = start.elapsed();

        let result_label = match &result {
            Ok(_) => "ok",
            Err(_) => "error",
        };

        counter!("veil_commands_total", "command" => verb, "keyring" => keyring_label.clone(), "result" => result_label).increment(1);
        histogram!("veil_command_duration_seconds", "command" => verb, "keyring" => keyring_label.clone()).record(duration.as_secs_f64());

        if !matches!(verb, "HEALTH" | "AUTH") {
            tracing::info!(
                target: "veil::audit",
                op = verb,
                keyring = keyring_label.as_str(),
                result = result_label,
                duration_ms = duration.as_millis() as u64,
                "command executed"
            );
        }

        match result {
            Ok(resp) => CommandResponse::Success(resp),
            Err(e) => CommandResponse::Error(e),
        }
    }

    async fn dispatch(&self, cmd: Command) -> Result<ResponseMap, CommandError> {
        match cmd {
            Command::Fuzzy(args) => {
                handlers::search::handle_search(
                    self.transit.as_ref(),
                    MatchMode::Fuzzy { max_distance: 2 },
                    &args,
                    &self.search_config,
                )
                .await
            }
            Command::Contains(args) => {
                handlers::search::handle_search(
                    self.transit.as_ref(),
                    MatchMode::Contains,
                    &args,
                    &self.search_config,
                )
                .await
            }
            Command::Exact(args) => {
                handlers::search::handle_search(
                    self.transit.as_ref(),
                    MatchMode::Exact,
                    &args,
                    &self.search_config,
                )
                .await
            }
            Command::Prefix(args) => {
                handlers::search::handle_search(
                    self.transit.as_ref(),
                    MatchMode::Prefix,
                    &args,
                    &self.search_config,
                )
                .await
            }
            Command::Index(args) => {
                handlers::index::handle_index(self.transit.as_ref(), &args).await
            }
            Command::Health => handlers::health::handle_health(self.transit.as_ref()).await,
            Command::ConfigGet { key } => match self.config.get(&key) {
                Some(v) => Ok(ResponseMap::ok()
                    .with("value", ResponseValue::String(v.value().clone()))
                    .with("source", ResponseValue::String("runtime".into()))),
                None => Err(CommandError::BadArg {
                    message: format!("unknown config key: {key}"),
                }),
            },
            Command::ConfigSet { key, value } => {
                if !self.config.contains_key(&key) {
                    return Err(CommandError::BadArg {
                        message: format!("unknown config key: {key}"),
                    });
                }
                self.config.insert(key.clone(), value);
                Ok(ResponseMap::ok())
            }
            Command::ConfigList => {
                let fields: Vec<_> = self
                    .config
                    .iter()
                    .map(|entry| {
                        (
                            entry.key().clone(),
                            ResponseValue::Map(
                                ResponseMap::ok()
                                    .with("value", ResponseValue::String(entry.value().clone()))
                                    .with("source", ResponseValue::String("runtime".into()))
                                    .with("mutable", ResponseValue::Boolean(true)),
                            ),
                        )
                    })
                    .collect();
                Ok(ResponseMap { fields })
            }
            Command::Auth { .. } => Ok(ResponseMap::ok()),
            Command::Pipeline(_) => unreachable!("pipeline handled above"),
        }
    }
}
