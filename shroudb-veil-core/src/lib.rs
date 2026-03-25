//! Core types for ShrouDB Veil — encrypted search over E2EE data.
//!
//! Search query types, match engine, result envelopes, and error types.
//! Veil has no dependency on Transit internals — it only knows about
//! ciphertexts as opaque strings.

pub mod error;
pub mod matcher;
pub mod query;
pub mod tokenizer;

pub use error::VeilError;
pub use matcher::{MatchMode, MatchResult, Matcher};
pub use query::{CiphertextEntry, FieldSelector, SearchRequest, SearchResponse, SearchResultEntry};
pub use tokenizer::{tokenize, tokenize_query};
