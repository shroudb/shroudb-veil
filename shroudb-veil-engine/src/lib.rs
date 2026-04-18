//! Store-backed blind index engine.
//!
//! This is the core Veil engine — blind index lifecycle management,
//! HMAC-based token derivation, and search operations.
//! Consumes the ShrouDB Store trait for persistence.

pub mod engine;
pub mod hmac_ops;
pub mod index_manager;
pub mod search;

#[cfg(test)]
mod test_support;
