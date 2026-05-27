//! reth-tdx — remote TDX TEE prover for taiko-mono / raiko2 (Shasta).
//!
//! Architecture summary (see README for details):
//!
//! * Runs **inside** the TDX-protected VM alongside the Nethermind L2 client.
//! * Exposes an HTTP API over which an external raiko2 instance requests proofs.
//! * Receives only L1-derived proposal data from the caller — never raw L2 blocks.
//! * Fetches the L2 block range itself from the local Nethermind JSON-RPC, then
//!   builds the `proof_carry_data` and ECDSA-signs it with the TEE-bound key.
//! * Owns its private key end-to-end: the key is generated in-VM and never leaves
//!   the TEE; the TDX attestation quote binds the key to the running image.

#![warn(missing_docs)]

pub mod aggregation;
pub mod attestation;
pub mod bootstrap;
pub mod config;
pub mod l2_client;
pub mod persistence;
pub mod proof;
pub mod proposal;
pub mod protocol;
pub mod runtime;
pub mod server;
pub mod signature;

pub use config::{Config, ServeOpts};
pub use runtime::{bootstrap, check, serve};
