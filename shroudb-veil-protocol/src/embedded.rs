//! Embedded Transit backend — runs Transit's engine in-process.
//!
//! No network hop, no serialization overhead. Plaintext stays in the same
//! process memory as the match engine.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use shroudb_transit_protocol::CommandDispatcher as TransitDispatcher;
use shroudb_transit_protocol::{Command as TransitCommand, CommandResponse, ResponseValue};

use crate::error::CommandError;
use crate::transit_backend::{DecryptOutput, EncryptOutput, HealthOutput, TransitBackend};

/// Embedded Transit backend wrapping an in-process Transit dispatcher.
pub struct EmbeddedTransit {
    dispatcher: Arc<TransitDispatcher>,
}

impl EmbeddedTransit {
    pub fn new(dispatcher: Arc<TransitDispatcher>) -> Self {
        Self { dispatcher }
    }
}

impl TransitBackend for EmbeddedTransit {
    async fn encrypt(
        &self,
        keyring: &str,
        plaintext: &[u8],
        context: Option<&str>,
    ) -> Result<EncryptOutput, CommandError> {
        let cmd = TransitCommand::Encrypt {
            keyring: keyring.to_string(),
            plaintext: STANDARD.encode(plaintext),
            context: context.map(|s| s.to_string()),
            key_version: None,
            convergent: false,
        };
        let resp = self.dispatcher.execute(cmd, None).await;
        extract_encrypt_result(resp)
    }

    async fn encrypt_convergent(
        &self,
        keyring: &str,
        plaintext: &[u8],
        context: &str,
    ) -> Result<EncryptOutput, CommandError> {
        let cmd = TransitCommand::Encrypt {
            keyring: keyring.to_string(),
            plaintext: STANDARD.encode(plaintext),
            context: Some(context.to_string()),
            key_version: None,
            convergent: true,
        };
        let resp = self.dispatcher.execute(cmd, None).await;
        extract_encrypt_result(resp)
    }

    async fn decrypt(
        &self,
        keyring: &str,
        ciphertext: &str,
        context: Option<&str>,
    ) -> Result<DecryptOutput, CommandError> {
        let cmd = TransitCommand::Decrypt {
            keyring: keyring.to_string(),
            ciphertext: ciphertext.to_string(),
            context: context.map(|s| s.to_string()),
        };
        let resp = self.dispatcher.execute(cmd, None).await;
        extract_decrypt_result(resp)
    }

    async fn decrypt_batch(
        &self,
        keyring: &str,
        ciphertexts: &[&str],
        context: Option<&str>,
    ) -> Result<Vec<Result<String, String>>, CommandError> {
        // In embedded mode, no pipeline overhead — just run each decrypt directly.
        // These are in-process calls with no network hop.
        let mut results = Vec::with_capacity(ciphertexts.len());
        for ct in ciphertexts {
            let cmd = TransitCommand::Decrypt {
                keyring: keyring.to_string(),
                ciphertext: ct.to_string(),
                context: context.map(|s| s.to_string()),
            };
            let resp = self.dispatcher.execute(cmd, None).await;
            match extract_decrypt_result(resp) {
                Ok(d) => results.push(Ok(d.plaintext_b64)),
                Err(e) => results.push(Err(e.to_string())),
            }
        }
        Ok(results)
    }

    async fn health(&self) -> Result<HealthOutput, CommandError> {
        let cmd = TransitCommand::Health { keyring: None };
        let resp = self.dispatcher.execute(cmd, None).await;
        match resp {
            CommandResponse::Success(map) => {
                let state = map
                    .fields
                    .iter()
                    .find_map(|(k, v)| {
                        if k == "state" {
                            if let ResponseValue::String(s) = v {
                                Some(s.clone())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "ok".to_string());
                Ok(HealthOutput { state })
            }
            CommandResponse::Error(e) => Err(CommandError::Transit(e.to_string())),
            _ => Ok(HealthOutput {
                state: "ok".to_string(),
            }),
        }
    }
}

fn extract_encrypt_result(resp: CommandResponse) -> Result<EncryptOutput, CommandError> {
    match resp {
        CommandResponse::Success(map) => {
            let mut ciphertext = None;
            let mut key_version = None;
            for (k, v) in &map.fields {
                match (k.as_str(), v) {
                    ("ciphertext", ResponseValue::String(s)) => ciphertext = Some(s.clone()),
                    ("key_version", ResponseValue::Integer(n)) => key_version = Some(*n),
                    _ => {}
                }
            }
            Ok(EncryptOutput {
                ciphertext: ciphertext
                    .ok_or_else(|| CommandError::Transit("missing ciphertext".into()))?,
                key_version: key_version
                    .ok_or_else(|| CommandError::Transit("missing key_version".into()))?,
            })
        }
        CommandResponse::Error(e) => Err(CommandError::Transit(e.to_string())),
        _ => Err(CommandError::Transit("unexpected response type".into())),
    }
}

fn extract_decrypt_result(resp: CommandResponse) -> Result<DecryptOutput, CommandError> {
    match resp {
        CommandResponse::Success(map) => {
            let plaintext = map
                .fields
                .iter()
                .find_map(|(k, v)| {
                    if k == "plaintext" {
                        if let ResponseValue::String(s) = v {
                            Some(s.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .ok_or_else(|| CommandError::Transit("missing plaintext".into()))?;
            Ok(DecryptOutput {
                plaintext_b64: plaintext,
            })
        }
        CommandResponse::Error(e) => Err(CommandError::Transit(e.to_string())),
        _ => Err(CommandError::Transit("unexpected response type".into())),
    }
}
