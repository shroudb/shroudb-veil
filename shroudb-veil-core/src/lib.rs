//! Core types for ShrouDB Veil.
//!
//! Blind index configuration, match modes, token sets, and error types.

pub mod error;
pub mod index;
pub mod matching;
pub mod tokenizer;

pub use error::VeilError;
pub use index::BlindIndex;
pub use matching::MatchMode;
