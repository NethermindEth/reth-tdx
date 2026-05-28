//! Wire protocol between an external raiko2 instance and reth-tdx.
//!
//! # Why a new schema (not raiko2-shasta-request-v1)
//!
//! raiko2's protocol (`raiko2-shasta-request-v1`) carries the full L2 block bodies
//! and execution witnesses because raiko2's other backends re-execute the blocks to
//! produce their attestation.
//!
//! reth-tdx is co-located with a trusted Nethermind L2 client inside the TDX VM
//! and fetches blocks itself over the local JSON-RPC. The caller therefore sends
//! only the L1-derived proposal fields (which the on-chain Shasta verifier will
//! cross-check independently when the proof is submitted). This both shrinks the
//! request payload and tightens the trust boundary: reth-tdx never accepts L2
//! state from the caller.

use alloy_primitives::{Address, B256};
use raiko2_protocol_shasta::shasta::{ProofCarryData, ShastaTransitionInput};
use serde::{Deserialize, Serialize};

/// Request schema for a single Shasta proposal proof. Increment the trailing
/// version number when the payload shape changes.
pub const RETH_TDX_SHASTA_REQUEST_SCHEMA: &str = "reth-tdx-shasta-request-v1";

/// Request schema for a Shasta aggregation proof.
pub const RETH_TDX_SHASTA_AGGREGATE_REQUEST_SCHEMA: &str = "reth-tdx-shasta-aggregate-request-v1";

/// Response schema shared by both proof endpoints.
pub const RETH_TDX_PROOF_RESPONSE_SCHEMA: &str = "reth-tdx-proof-v1";

// ─────────────────────────── Proposal proof ───────────────────────────

/// Top-level request envelope for `POST /prove/shasta`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShastaProveRequest {
    /// Schema discriminator — must equal [`RETH_TDX_SHASTA_REQUEST_SCHEMA`].
    pub schema: String,
    /// L1-derived proposal data. reth-tdx fetches the corresponding L2 blocks
    /// itself from the local Nethermind endpoint.
    pub payload: ShastaProvePayload,
}

/// L1-derived proposal data passed by the caller. Everything in here is
/// independently verifiable by the on-chain Shasta verifier against L1 state at
/// proof-submission time, so it is safe to trust without an L1 RPC inside the
/// TEE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShastaProvePayload {
    /// L2 chain id. Must match the locally configured `l2_chain_id`.
    pub chain_id: u64,
    /// On-chain Shasta verifier address. Must match the locally configured
    /// `verifier`.
    pub verifier: Address,
    /// Shasta proposal id — used as the L2 block number to fetch locally
    /// (proposal_id ↔ L2 block number is 1:1 in Shasta).
    pub proposal_id: u64,
    /// L1 proposal hash. Cross-checked on L1 by the Shasta verifier.
    pub proposal_hash: B256,
    /// Parent proposal hash from the Shasta proposal chain.
    pub parent_proposal_hash: B256,
    /// The EOA the prover will submit the proof from. Bound into the signed
    /// `shasta_aggregation_output` per Shasta's actual-prover field.
    pub actual_prover: Address,
    /// Transition input (proposer + timestamp) from the L1 proposal event.
    pub transition: ShastaTransitionInput,
}

// ─────────────────────────── Aggregation proof ───────────────────────────

/// Top-level request envelope for `POST /prove/shasta-aggregate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShastaAggregateRequest {
    /// Schema discriminator — must equal
    /// [`RETH_TDX_SHASTA_AGGREGATE_REQUEST_SCHEMA`].
    pub schema: String,
    /// One entry per sub-proof being aggregated.
    pub payload: ShastaAggregatePayload,
}

/// Aggregation payload — a flat list of previously-signed sub-proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShastaAggregatePayload {
    /// Sub-proofs to fold into a single aggregation signature.
    pub proofs: Vec<ShastaAggregateProof>,
}

/// One previously-signed sub-proof. Each carries its own `ShastaProvePayload`
/// plus the proof bytes and signing hash from when it was originally produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShastaAggregateProof {
    /// L1-derived data the sub-proof was bound to.
    pub payload: ShastaProvePayload,
    /// Original signing hash (the value the ECDSA signature was made over).
    pub input: B256,
    /// Hex-encoded 89-byte sub-proof.
    pub proof: String,
}

// ─────────────────────────── Response ───────────────────────────

/// Response envelope shared by both proof endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResponse {
    /// Schema discriminator — equals [`RETH_TDX_PROOF_RESPONSE_SCHEMA`].
    pub schema: String,
    /// `ok` or `error`.
    pub status: ProofStatus,
    /// Present on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ProofResult>,
    /// Present on error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProofError>,
}

/// Response status discriminator.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    /// Proof generated successfully.
    Ok,
    /// Proof generation failed.
    Error,
}

/// Successful proof payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResult {
    /// Hex-encoded 89-byte TDX proof.
    pub proof: String,
    /// Hex-encoded TDX attestation quote bound to the signing hash.
    pub quote: String,
    /// Hex-encoded signing hash (the value the ECDSA signature was made over).
    pub input: String,
    /// Bootstrap public key / instance address (echoed for caller convenience).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_address: Option<String>,
    /// The exact `ProofCarryData` vector reth-tdx used to build the Shasta
    /// commitment whose hash was signed. Callers need this to compute
    /// `_commitmentHash = hashCommitment(commitment)` for on-chain
    /// `verifyProof`. Length 1 for proposal proofs, N for aggregation
    /// (one entry per sub-proof in original order).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_carry_data_vec: Option<Vec<ProofCarryData>>,
}

/// Error payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofError {
    /// Short machine-readable code.
    pub code: String,
    /// Human-readable explanation.
    pub message: String,
}

// ─────────────────────────── Bootstrap (registration) ───────────────────────────

/// Response body for `GET /bootstrap`. This is what `xtask register-tdx` reads to
/// register the prover on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapResponse {
    /// One of `tdx`, `azure`, `gcp`, `simulator`.
    pub issuer_type: String,
    /// Hex-encoded bootstrap public key (instance address).
    pub public_key: String,
    /// Hex-encoded TDX attestation quote over the public key.
    pub quote: String,
    /// Hex-encoded 32-byte random nonce used to derive the attestation extraData.
    pub nonce: String,
    /// Issuer-specific metadata (PCRs for Azure vTPM, etc.).
    pub metadata: serde_json::Value,
}
