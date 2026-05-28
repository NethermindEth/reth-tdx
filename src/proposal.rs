//! Proposal-proof orchestration: combine L1-derived request fields with L2
//! state fetched locally, build the Shasta `ProofCarryData`, compute the
//! signing hash, and sign it with the TDX-bound bootstrap key.

use alloy_primitives::Uint;
use anyhow::{Context, Result, anyhow};
use raiko2_primitives_shasta::instance::{
    build_shasta_commitment_from_proof_carry_data_vec, shasta_aggregation_output,
};
use raiko2_protocol_shasta::shasta::{Checkpoint, ProofCarryData, TransitionInputData};
use tracing::info;

use crate::{
    Config,
    l2_client::{L2BlockHeader, L2Client},
    persistence,
    proof::{ProveData, prove},
    protocol::{ProofResult, RETH_TDX_PROOF_RESPONSE_SCHEMA, ShastaProvePayload},
    signature::address_from_private_key,
};

/// Output of a single-proposal prove call.
#[derive(Debug, Clone)]
pub struct SignedProposal {
    /// 89-byte TDX proof (hex).
    pub proof: String,
    /// TDX attestation quote (hex).
    pub quote: String,
    /// Signing hash (the value the ECDSA signature was made over, hex).
    pub input: String,
    /// Bootstrap public key / instance address (hex).
    pub instance_address: String,
    /// Exact `ProofCarryData` vector used to build the signed commitment.
    /// Returned so callers can compute `hashCommitment(commitment)` for
    /// on-chain `verifyProof` without re-fetching the local L2 state.
    pub carry_data_vec: Vec<ProofCarryData>,
}

/// Validate the caller's chain_id / verifier against the prover's static config
/// before doing any expensive work.
fn validate_payload(config: &Config, payload: &ShastaProvePayload) -> Result<()> {
    if payload.chain_id != config.l2_chain_id {
        return Err(anyhow!(
            "request chain_id {} does not match prover's configured chain_id {}",
            payload.chain_id,
            config.l2_chain_id
        ));
    }
    if payload.verifier != config.verifier {
        return Err(anyhow!(
            "request verifier {} does not match prover's configured verifier {}",
            payload.verifier,
            config.verifier
        ));
    }
    Ok(())
}

/// Build a Shasta `ProofCarryData` for a single proposal by combining the
/// caller-supplied L1 fields with the L2 header fetched from the local
/// Nethermind. Internal helper exposed for `proposal_carry_data_from_header`
/// reuse in tests.
#[must_use]
pub fn proposal_carry_data_from_header(
    payload: &ShastaProvePayload,
    header: &L2BlockHeader,
) -> ProofCarryData {
    ProofCarryData {
        chain_id: payload.chain_id,
        verifier: payload.verifier,
        transition_input: TransitionInputData {
            proposal_id: payload.proposal_id,
            proposal_hash: payload.proposal_hash,
            parent_proposal_hash: payload.parent_proposal_hash,
            parent_block_hash: header.parent_hash,
            actual_prover: payload.actual_prover,
            transition: payload.transition.clone(),
            checkpoint: Checkpoint {
                blockNumber: Uint::from(header.number),
                blockHash: header.hash,
                stateRoot: header.state_root,
            },
        },
    }
}

/// Sign one Shasta proposal's `ProofCarryData`.
///
/// 1. Validates the request matches the prover's configured chain_id / verifier.
/// 2. Fetches L2 block N (where N = `payload.proposal_id`) from the local
///    Nethermind RPC.
/// 3. Builds the full `ProofCarryData` using the caller's L1 fields plus the
///    L2 block's hash / state_root / parent_hash.
/// 4. Computes `shasta_aggregation_output(commitment, …)` — the same hash the
///    on-chain Shasta verifier will recover from the signature.
/// 5. Signs with the bootstrap key and produces a TDX attestation quote bound
///    to the same hash.
///
/// # Errors
///
/// Returns an error if validation fails, the local L2 fetch fails, the
/// commitment cannot be built (continuity broken), or signing / attestation
/// fail.
pub async fn sign_proposal(
    config: &Config,
    l2_client: &L2Client,
    payload: ShastaProvePayload,
) -> Result<SignedProposal> {
    validate_payload(config, &payload)?;

    info!(
        proposal_id = payload.proposal_id,
        "fetching local L2 block for TDX proposal proof",
    );
    let header = l2_client
        .fetch_block_header(payload.proposal_id)
        .await
        .with_context(|| format!("fetching L2 block {} from local node", payload.proposal_id))?;

    let private_key = persistence::load_private_key(config.home.as_deref())
        .context("failed to load TDX bootstrap key")?;
    let tdx_instance = address_from_private_key(&private_key);

    let carry = proposal_carry_data_from_header(&payload, &header);

    let commitment =
        build_shasta_commitment_from_proof_carry_data_vec(std::slice::from_ref(&carry))
            .ok_or_else(|| anyhow!("failed to build Shasta commitment from carry data"))?;

    let signing_hash =
        shasta_aggregation_output(&commitment, carry.chain_id, carry.verifier, tdx_instance);

    let ProveData { proof, quote } = prove(
        &config.tdxs_socket,
        config.instance_id,
        &private_key,
        signing_hash,
    )
    .await
    .context("TDX proposal proof generation failed")?;

    Ok(SignedProposal {
        carry_data_vec: vec![carry.clone()],
        proof: format!("0x{}", hex::encode(proof)),
        quote: hex::encode(quote),
        input: format!("{signing_hash:?}"),
        instance_address: tdx_instance.to_string(),
    })
}

impl From<SignedProposal> for ProofResult {
    fn from(value: SignedProposal) -> Self {
        Self {
            proof: value.proof,
            quote: value.quote,
            input: value.input,
            instance_address: Some(value.instance_address),
            proof_carry_data_vec: Some(value.carry_data_vec),
        }
    }
}

/// Schema discriminator echoed in every response envelope.
pub const RESPONSE_SCHEMA: &str = RETH_TDX_PROOF_RESPONSE_SCHEMA;
