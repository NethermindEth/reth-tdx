//! Configuration types for the reth-tdx binary.
//!
//! All values are populated at image-build time via the mustache templates in
//! nethermind-tdx (`taiko-tdx-prover/mkosi.extra/etc/reth-tdx/`). Operators do
//! **not** pass the L2 RPC URL on the command line — it is hardcoded to the
//! local Nethermind endpoint that ships in the image. Allowing an operator to
//! override the L2 RPC would let a malicious caller point reth-tdx at an
//! untrusted node, defeating the purpose of running the prover inside the TEE.

use std::net::SocketAddr;

use clap::Args;

/// L2 JSON-RPC URL used to fetch blocks from the locally co-resident Nethermind
/// execution client. Hardcoded to the localhost port baked into the
/// nethermind-tdx image (see `taiko-tdx-prover/mkosi.extra/.env.mustache`,
/// `L2_HTTP_PORT=8547`).
pub const LOCAL_L2_RPC_URL: &str = "http://127.0.0.1:8547";

/// Global configuration loaded from CLI flags (or, where appropriate, environment
/// variables baked in by the image).
#[derive(Debug, Clone, Args)]
pub struct Config {
    /// Path to the tdxs attestation daemon Unix socket.
    #[arg(long, env = "RETH_TDX_SOCKET", default_value = "/var/tdxs.sock")]
    pub tdxs_socket: String,

    /// Persistent directory for the bootstrap key + record.
    ///
    /// Defaults to `$HOME/.config/reth-tdx/` when unset.
    #[arg(long, env = "RETH_TDX_HOME")]
    pub home: Option<String>,

    /// On-chain verifier instance ID (4-byte big-endian field of the 89-byte
    /// proof wire format). Matches the legacy SGX prover's instance id slot so
    /// the same `SgxVerifier` ABI accepts TDX proofs.
    #[arg(long, env = "RETH_TDX_INSTANCE_ID", default_value_t = 0)]
    pub instance_id: u32,

    /// L2 chain id (Taiko). Bound into the signed `shasta_aggregation_output`.
    #[arg(long, env = "RETH_TDX_L2_CHAIN_ID")]
    pub l2_chain_id: u64,

    /// On-chain Shasta verifier address. Bound into `shasta_aggregation_output`.
    #[arg(long, env = "RETH_TDX_VERIFIER")]
    pub verifier: alloy_primitives::Address,
}

/// `serve` subcommand options — bind address only. Everything else flows through
/// the global [`Config`].
#[derive(Debug, Clone, Args)]
pub struct ServeOpts {
    /// Address to bind the HTTP server.
    #[arg(long, env = "RETH_TDX_BIND", default_value = "0.0.0.0:8080")]
    pub bind: SocketAddr,
}
