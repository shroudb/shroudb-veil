//! RESP3 wire protocol support for ShrouDB Veil.
//!
//! Re-exports the canonical `Resp3Frame` and `ProtocolError` from `shroudb-protocol-wire`,
//! and adds Veil-specific command parsing and response serialization.

pub mod parse_command;
pub mod serialize;

pub use shroudb_protocol_wire::{ProtocolError, Resp3Frame};
pub use shroudb_protocol_wire::{reader, writer};
