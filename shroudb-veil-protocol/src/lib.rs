//! Protocol layer for ShrouDB Veil.
//!
//! Command parsing, dispatch, handler execution, and response serialization.
//! Veil delegates all cryptographic operations to Transit — either an in-process
//! embedded engine or a remote server over TCP.

pub mod command;
pub mod command_parser;
pub mod dispatch;
#[cfg(feature = "embedded")]
pub mod embedded;
pub mod error;
pub mod handlers;
pub mod remote;
pub mod response;
pub mod search_engine;
pub mod serialize;
pub mod transit_backend;

pub use command::Command;
pub use dispatch::CommandDispatcher;
pub use error::CommandError;
pub use response::{CommandResponse, ResponseMap, ResponseValue};
pub use transit_backend::TransitBackend;
