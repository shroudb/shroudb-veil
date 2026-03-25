/// Protocol-agnostic command representation for ShrouDB Veil.
///
/// Each match mode is a first-class command verb:
///   FUZZY <keyring> QUERY <query> [FIELD <f>] [CONTEXT <aad>] [LIMIT <n>] [REWRAP] CIPHERTEXTS <ct1> ...
///   CONTAINS <keyring> QUERY <query> ...
///   EXACT <keyring> QUERY <query> ...
///   PREFIX <keyring> QUERY <query> ...
///
/// INDEX encrypts plaintext and generates search tokens:
///   INDEX <keyring> <b64_plaintext> [FIELD <f>] [CONTEXT <aad>]
#[derive(Debug, Clone)]
pub enum Command {
    /// Fuzzy search (Levenshtein distance on word boundaries).
    Fuzzy(SearchArgs),
    /// Substring search (case-insensitive contains).
    Contains(SearchArgs),
    /// Exact equality search (case-insensitive).
    Exact(SearchArgs),
    /// Prefix search (word-boundary aware).
    Prefix(SearchArgs),
    /// Encrypt plaintext and generate search tokens.
    Index(IndexArgs),
    /// Health check.
    Health,
    /// Authenticate the connection.
    Auth { token: String },
    /// Pipeline of sub-commands.
    Pipeline(Vec<Command>),
}

/// Common arguments for all search commands.
#[derive(Debug, Clone)]
pub struct SearchArgs {
    pub keyring: String,
    pub query: String,
    pub field: Option<String>,
    pub context: Option<String>,
    pub limit: Option<usize>,
    /// If true, re-encrypt matches with the active key version.
    pub rewrap: bool,
    /// Search entries: ciphertext + optional pre-computed tokens.
    pub entries: Vec<SearchEntry>,
}

/// A single entry in a search request.
#[derive(Debug, Clone)]
pub struct SearchEntry {
    pub ciphertext: String,
    pub tokens: Option<Vec<String>>,
}

/// Arguments for the INDEX command.
#[derive(Debug, Clone)]
pub struct IndexArgs {
    pub keyring: String,
    pub plaintext_b64: String,
    pub field: Option<String>,
    pub context: Option<String>,
}

impl Command {
    /// Returns the keyring name, if applicable.
    pub fn keyring(&self) -> Option<&str> {
        match self {
            Self::Fuzzy(a) | Self::Contains(a) | Self::Exact(a) | Self::Prefix(a) => {
                Some(&a.keyring)
            }
            Self::Index(a) => Some(&a.keyring),
            Self::Health | Self::Auth { .. } | Self::Pipeline(_) => None,
        }
    }
}

/// Returns the verb string for metrics/logging.
pub fn command_verb(cmd: &Command) -> &'static str {
    match cmd {
        Command::Fuzzy(_) => "FUZZY",
        Command::Contains(_) => "CONTAINS",
        Command::Exact(_) => "EXACT",
        Command::Prefix(_) => "PREFIX",
        Command::Index(_) => "INDEX",
        Command::Health => "HEALTH",
        Command::Auth { .. } => "AUTH",
        Command::Pipeline(_) => "PIPELINE",
    }
}
