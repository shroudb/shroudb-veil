//! Remote Transit backend — proxies operations over TCP to an external Transit server.

use shroudb_transit_client::{Response, TransitClient};
use tokio::sync::Mutex;

use crate::error::CommandError;
use crate::transit_backend::{DecryptOutput, EncryptOutput, HealthOutput, TransitBackend};

/// Configuration for connecting to a remote Transit server.
#[derive(Debug, Clone)]
pub struct RemoteTransitConfig {
    /// Transit server address (e.g., "127.0.0.1:6499").
    pub addr: String,
    /// Whether to use TLS for the Transit connection.
    pub tls: bool,
    /// Optional auth token for Transit.
    pub auth_token: Option<String>,
    /// Number of connections in the pool.
    pub pool_size: usize,
}

/// Remote Transit backend with connection pooling and auto-reconnect.
pub struct RemoteTransit {
    config: RemoteTransitConfig,
    connections: Vec<Mutex<Option<TransitClient>>>,
    next: std::sync::atomic::AtomicUsize,
}

impl RemoteTransit {
    /// Create a new remote backend. Connections are established lazily.
    pub fn new(config: RemoteTransitConfig) -> Self {
        let pool_size = config.pool_size.max(1);
        let connections = (0..pool_size).map(|_| Mutex::new(None)).collect();
        Self {
            config,
            connections,
            next: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Get or create a connection for the given slot.
    async fn get_client(&self, slot: usize) -> Result<TransitClient, CommandError> {
        let mut guard = self.connections[slot].lock().await;
        if let Some(ref mut client) = *guard {
            // Quick health check to verify the connection is still alive.
            if client.health().await.is_ok() {
                // Take ownership temporarily — caller must return it via return_client.
                return Ok(guard.take().unwrap());
            }
            tracing::debug!(slot = slot, "discarding stale remote Transit connection");
        }
        // Create a new connection.
        let client = self.connect_new().await?;
        Ok(client)
    }

    /// Return a connection to the pool.
    async fn return_client(&self, slot: usize, client: TransitClient) {
        let mut guard = self.connections[slot].lock().await;
        *guard = Some(client);
    }

    fn pick_slot(&self) -> usize {
        self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.connections.len()
    }

    async fn connect_new(&self) -> Result<TransitClient, CommandError> {
        let mut client = if self.config.tls {
            TransitClient::connect_tls(&self.config.addr)
                .await
                .map_err(|e| CommandError::Transit(e.to_string()))?
        } else {
            TransitClient::connect(&self.config.addr)
                .await
                .map_err(|e| CommandError::Transit(e.to_string()))?
        };

        if let Some(ref token) = self.config.auth_token {
            client
                .auth(token)
                .await
                .map_err(|e| CommandError::Transit(e.to_string()))?;
        }

        Ok(client)
    }
}

impl TransitBackend for RemoteTransit {
    async fn encrypt(
        &self,
        keyring: &str,
        plaintext: &[u8],
        context: Option<&str>,
    ) -> Result<EncryptOutput, CommandError> {
        let slot = self.pick_slot();
        let mut client = self.get_client(slot).await?;
        let result = client
            .encrypt(keyring, plaintext, context)
            .await
            .map_err(|e| CommandError::Transit(e.to_string()))?;
        self.return_client(slot, client).await;
        Ok(EncryptOutput {
            ciphertext: result.ciphertext,
            key_version: result.key_version,
        })
    }

    async fn encrypt_convergent(
        &self,
        keyring: &str,
        plaintext: &[u8],
        context: &str,
    ) -> Result<EncryptOutput, CommandError> {
        let slot = self.pick_slot();
        let mut client = self.get_client(slot).await?;
        let result = client
            .encrypt_convergent(keyring, plaintext, context)
            .await
            .map_err(|e| CommandError::Transit(e.to_string()))?;
        self.return_client(slot, client).await;
        Ok(EncryptOutput {
            ciphertext: result.ciphertext,
            key_version: result.key_version,
        })
    }

    async fn decrypt(
        &self,
        keyring: &str,
        ciphertext: &str,
        context: Option<&str>,
    ) -> Result<DecryptOutput, CommandError> {
        let slot = self.pick_slot();
        let mut client = self.get_client(slot).await?;
        let result = client
            .decrypt(keyring, ciphertext, context)
            .await
            .map_err(|e| CommandError::Transit(e.to_string()))?;
        self.return_client(slot, client).await;
        Ok(DecryptOutput {
            plaintext_b64: result.plaintext,
        })
    }

    async fn decrypt_batch(
        &self,
        keyring: &str,
        ciphertexts: &[&str],
        context: Option<&str>,
    ) -> Result<Vec<Result<String, String>>, CommandError> {
        if ciphertexts.is_empty() {
            return Ok(Vec::new());
        }

        if ciphertexts.len() == 1 {
            let slot = self.pick_slot();
            let mut client = self.get_client(slot).await?;
            let result = client.decrypt(keyring, ciphertexts[0], context).await;
            self.return_client(slot, client).await;
            return Ok(vec![result.map(|r| r.plaintext).map_err(|e| e.to_string())]);
        }

        // Build PIPELINE DECRYPT command.
        let mut tokens: Vec<String> = Vec::with_capacity(ciphertexts.len() * 4 + 2);
        tokens.push("PIPELINE".into());
        for ct in ciphertexts {
            tokens.push("DECRYPT".into());
            tokens.push(keyring.into());
            tokens.push((*ct).into());
            if let Some(ctx) = context {
                tokens.push("CONTEXT".into());
                tokens.push(ctx.into());
            }
        }
        tokens.push("END".into());

        let refs: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();

        let slot = self.pick_slot();
        let mut client = self.get_client(slot).await?;
        let response = client
            .raw_command(&refs)
            .await
            .map_err(|e| CommandError::Transit(e.to_string()))?;
        self.return_client(slot, client).await;

        match response {
            Response::Array(items) => {
                let mut results = Vec::with_capacity(items.len());
                for item in items {
                    match &item {
                        Response::Map(entries) => {
                            let pt = entries.iter().find_map(|(k, v)| {
                                if let (Response::String(key), Response::String(val)) = (k, v)
                                    && key == "plaintext"
                                {
                                    Some(val.clone())
                                } else {
                                    None
                                }
                            });
                            match pt {
                                Some(p) => results.push(Ok(p)),
                                None => {
                                    results.push(Err("missing plaintext in response".to_string()))
                                }
                            }
                        }
                        Response::Error(e) => results.push(Err(e.clone())),
                        other => results.push(Err(format!(
                            "unexpected response type: {}",
                            other.type_name()
                        ))),
                    }
                }
                Ok(results)
            }
            Response::Error(e) => Err(CommandError::Transit(e)),
            other => Err(CommandError::Transit(format!(
                "expected Array from PIPELINE, got {}",
                other.type_name()
            ))),
        }
    }

    async fn health(&self) -> Result<HealthOutput, CommandError> {
        let slot = self.pick_slot();
        let mut client = self.get_client(slot).await?;
        let result = client
            .health()
            .await
            .map_err(|e| CommandError::Transit(e.to_string()))?;
        self.return_client(slot, client).await;
        Ok(HealthOutput {
            state: result.state,
        })
    }
}
