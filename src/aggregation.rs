//! Aggregation-proof orchestration: combine a batch of previously-signed
//! sub-proofs into a single TDX aggregation signature.
//!
//! Mirrors [`crate::proposal`] but consumes a list of `ShastaAggregateProof`
//! entries (each already bound to its own carry data + signing hash) and emits
//! one signed aggregation hash.

use alloy_primitives::B256;
use anyhow::{Context, Result, anyhow};
use raiko2_primitives_shasta::instance::{
    build_shasta_commitment_from_proof_carry_data_vec, shasta_aggregation_output,
};
use raiko2_protocol_shasta::shasta::ProofCarryData;
use tracing::info;

use crate::{
    Config,
    l2_client::L2Client,
    persistence,
    proof::{ProveAggregationData, prove_shasta_aggregation},
    proposal::{SignedProposal, proposal_carry_data_from_header},
    protocol::ShastaAggregateProof,
    signature::address_from_private_key,
};

/// Sign a Shasta aggregation hash over a batch of sub-proofs.
///
/// Each sub-proof carries its own `ShastaProvePayload`. For every sub-proof
/// reth-tdx fetches the corresponding L2 block from the local Nethermind to
/// reconstruct the canonical `ProofCarryData` (the same way `sign_proposal`
/// does it), then verifies the supplied sub-proof signatures and aggregates.
///
/// # Errors
///
/// Returns an error if any L2 fetch fails, any sub-proof's payload disagrees
/// with the prover's configured chain_id / verifier, the carry-data chain is
/// not continuous, sub-proof verification fails, or signing / attestation fail.
pub async fn sign_aggregation(
    config: &Config,
    l2_client: &L2Client,
    sub_proofs: Vec<ShastaAggregateProof>,
) -> Result<SignedProposal> {
    if sub_proofs.is_empty() {
        return Err(anyhow!("aggregate request has no sub-proofs"));
    }

    info!(
        count = sub_proofs.len(),
        "rebuilding aggregation carry data"
    );

    let private_key = persistence::load_private_key(config.home.as_deref())
        .context("failed to load TDX bootstrap key")?;
    let tdx_instance = address_from_private_key(&private_key);

    let mut carry_vec: Vec<ProofCarryData> = Vec::with_capacity(sub_proofs.len());
    let mut sub_proof_pairs: Vec<(Vec<u8>, B256)> = Vec::with_capacity(sub_proofs.len());

    for (index, sub) in sub_proofs.iter().enumerate() {
        // Per-payload chain-id / verifier check — refuse to aggregate proofs
        // claimed for a different deployment.
        if sub.payload.chain_id != config.l2_chain_id {
            return Err(anyhow!(
                "sub-proof {index} chain_id {} != prover's chain_id {}",
                sub.payload.chain_id,
                config.l2_chain_id
            ));
        }
        if sub.payload.verifier != config.verifier {
            return Err(anyhow!(
                "sub-proof {index} verifier {} != prover's verifier {}",
                sub.payload.verifier,
                config.verifier
            ));
        }

        let header = l2_client
            .fetch_block_header(sub.payload.proposal_id)
            .await
            .with_context(|| {
                format!(
                    "fetching L2 block {} for aggregation sub-proof {}",
                    sub.payload.proposal_id, index
                )
            })?;

        let carry = proposal_carry_data_from_header(&sub.payload, &header);

        // Cross-check the rebuilt carry against the original signing hash:
        // a sub-proof's signing hash is shasta_aggregation_output over its
        // single-element commitment, so if the locally re-fetched L2 block
        // differs from the one the sub-proof was signed against (reorg, drift),
        // the recomputed hash won't match sub.input. Catching this here avoids
        // signing an aggregation over commitments the sub-proofs never covered.
        let single_commitment =
            build_shasta_commitment_from_proof_carry_data_vec(std::slice::from_ref(&carry))
                .ok_or_else(|| {
                    anyhow!("failed to build single-proof commitment for sub-proof {index}")
                })?;
        let expected_input = shasta_aggregation_output(
            &single_commitment,
            sub.payload.chain_id,
            sub.payload.verifier,
            tdx_instance,
        );
        if expected_input != sub.input {
            return Err(anyhow!(
                "sub-proof {index} rebuilt carry data hashes to {expected_input:?} \
                 but original sub-proof signed over {:?}; the local L2 state may \
                 have changed since the sub-proof was produced",
                sub.input
            ));
        }

        carry_vec.push(carry);

        let proof_bytes = hex::decode(sub.proof.trim_start_matches("0x"))
            .with_context(|| format!("sub-proof {index} proof bytes are not valid hex"))?;
        sub_proof_pairs.push((proof_bytes, sub.input));
    }

    let commitment = build_shasta_commitment_from_proof_carry_data_vec(&carry_vec)
        .ok_or_else(|| anyhow!("failed to build aggregation commitment (chain not continuous)"))?;
    let first = carry_vec.first().expect("non-empty checked above");
    let aggregation_hash =
        shasta_aggregation_output(&commitment, first.chain_id, first.verifier, tdx_instance);

    let ProveAggregationData {
        proof,
        quote,
        aggregation_hash,
    } = prove_shasta_aggregation(
        &config.tdxs_socket,
        &private_key,
        &sub_proof_pairs,
        aggregation_hash,
    )
    .await
    .context("TDX aggregation proof generation failed")?;

    Ok(SignedProposal {
        carry_data_vec: carry_vec,
        proof: format!("0x{}", hex::encode(proof)),
        quote: hex::encode(quote),
        input: format!("{aggregation_hash:?}"),
        instance_address: tdx_instance.to_string(),
    })
}
