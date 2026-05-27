//! TDX proof construction and attestation quote generation.
//!
//! [`TdxProof`] is the 89-byte canonical wire format
//! (`instance_id(4) || address(20) || signature(65)`) for both proposal and
//! aggregation proofs. It matches the legacy `SgxVerifier` ABI byte-for-byte so
//! TDX proofs slot into any `ComposeVerifier` configuration that already
//! accepts the SGX-style proof shape.

use alloy_primitives::{Address, B256};
use anyhow::{Result, anyhow};
use rand::Rng;
use tracing::info;

use crate::{
    attestation,
    signature::{address_from_private_key, recover_signer, sign_message},
};

/// Wire size: `instance_id(4) || address(20) || signature(65)`.
pub const TDX_PROOF_SIZE: usize = 89;

// ─────────────────────────── Proof structure ───────────────────────────

/// A single TDX proof (89 bytes).
#[derive(Debug)]
pub struct TdxProof {
    data: [u8; TDX_PROOF_SIZE],
}

impl TdxProof {
    /// Build a new proof from its components.
    #[must_use]
    pub fn new(instance_id: u32, public_key: &Address, signature: &[u8; 65]) -> Self {
        let mut data = [0u8; TDX_PROOF_SIZE];
        data[0..4].copy_from_slice(&instance_id.to_be_bytes());
        data[4..24].copy_from_slice(public_key.as_slice());
        data[24..89].copy_from_slice(signature);
        Self { data }
    }

    /// Parse from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice length does not match the expected
    /// proof size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != TDX_PROOF_SIZE {
            return Err(anyhow!(
                "Invalid proof size: expected {TDX_PROOF_SIZE}, got {}",
                bytes.len()
            ));
        }
        let mut data = [0u8; TDX_PROOF_SIZE];
        data.copy_from_slice(bytes);
        Ok(Self { data })
    }

    /// Extract the `instance_id` field (bytes 0..4, big-endian).
    #[must_use]
    #[allow(dead_code)]
    pub fn instance_id(&self) -> u32 {
        u32::from_be_bytes(self.data[0..4].try_into().unwrap())
    }

    /// Extract the prover address (bytes 4..24).
    #[must_use]
    pub fn public_key(&self) -> Address {
        Address::from_slice(&self.data[4..24])
    }

    /// Extract the ECDSA signature (bytes 24..89).
    #[must_use]
    pub fn signature(&self) -> [u8; 65] {
        self.data[24..89].try_into().unwrap()
    }

    /// Consume and return the raw bytes.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.data.to_vec()
    }
}

// ─────────────────────────── Quote generation ───────────────────────────

/// Generate a TDX attestation quote for arbitrary 32-byte user data.
///
/// Returns `(attestation_doc, nonce)`.
///
/// # Errors
///
/// Returns an error if the attestation service is unreachable.
pub async fn generate_tdx_quote(
    socket_path: &str,
    user_report_data: &B256,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let nonce: [u8; 32] = rand::thread_rng().r#gen();
    let nonce = nonce.to_vec();

    info!("Requesting TDX attestation from: {socket_path}");
    let attestation_doc =
        attestation::issue_attestation(socket_path, user_report_data.as_slice(), &nonce).await?;

    Ok((attestation_doc, nonce))
}

/// Generate a TDX attestation quote embedding the prover's public key (for
/// bootstrap).
///
/// # Errors
///
/// Returns an error if the attestation service is unreachable.
pub async fn generate_tdx_quote_from_public_key(
    socket_path: &str,
    public_key: &Address,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut padded = [0u8; 32];
    padded[..20].copy_from_slice(public_key.as_slice());
    generate_tdx_quote(socket_path, &B256::from(padded)).await
}

/// Retrieve metadata from the attestation service.
///
/// # Errors
///
/// Returns an error if the attestation service is unreachable.
pub async fn get_tdx_metadata(socket_path: &str) -> Result<attestation::MetadataResponseData> {
    attestation::metadata(socket_path).await
}

// ─────────────────────────── Single-proof construction ───────────────────────────

/// Output of a single-proof generation.
pub struct ProveData {
    /// 89-byte proof.
    pub proof: Vec<u8>,
    /// TDX attestation quote bound to the same signing hash.
    pub quote: Vec<u8>,
}

/// Generate a TDX proof for the given signing hash.
///
/// Signs the hash with the supplied private key, builds the 89-byte proof, and
/// produces a TDX attestation quote bound to the same hash.
///
/// # Errors
///
/// Returns an error if signing fails or the attestation service is unreachable.
pub async fn prove(
    socket_path: &str,
    instance_id: u32,
    private_key: &secp256k1::SecretKey,
    instance_hash: B256,
) -> Result<ProveData> {
    let address = address_from_private_key(private_key);

    let signature = sign_message(private_key, &instance_hash)?;
    let proof = TdxProof::new(instance_id, &address, &signature).into_vec();
    let (quote, _nonce) = generate_tdx_quote(socket_path, &instance_hash).await?;

    Ok(ProveData { proof, quote })
}

// ─────────────────────────── Aggregation construction ───────────────────────────

/// Output of an aggregation proof generation.
pub struct ProveAggregationData {
    /// 89-byte aggregation proof.
    pub proof: Vec<u8>,
    /// TDX attestation quote bound to the aggregation hash.
    pub quote: Vec<u8>,
    /// The aggregation hash the signature was made over (echoed for caller
    /// convenience — they would otherwise have to recompute it).
    pub aggregation_hash: B256,
}

/// Generate a Shasta TDX aggregation proof.
///
/// Verifies every sub-proof was signed by the same instance (no key rotation
/// in Shasta), then signs the aggregation hash with the current key.
///
/// # Errors
///
/// Returns an error if sub-proof verification fails or the attestation service
/// is unreachable.
pub async fn prove_shasta_aggregation(
    socket_path: &str,
    instance_id: u32,
    private_key: &secp256k1::SecretKey,
    sub_proofs: &[(Vec<u8>, B256)],
    aggregation_hash: B256,
) -> Result<ProveAggregationData> {
    let expected_instance = verify_sub_proofs(sub_proofs)?;

    // In Shasta the prover key cannot rotate between a sub-proof and the
    // aggregation: the on-chain verifier reads the signer from the signature
    // and expects it to match every sub-proof's signer.
    let new_instance = address_from_private_key(private_key);

    if new_instance != expected_instance {
        return Err(anyhow!(
            "Shasta aggregation does not allow key rotation: local instance {new_instance} does not match sub-proofs instance {expected_instance}"
        ));
    }

    let signature = sign_message(private_key, &aggregation_hash)?;
    let proof = TdxProof::new(instance_id, &new_instance, &signature).into_vec();
    let (quote, _nonce) = generate_tdx_quote(socket_path, &aggregation_hash).await?;

    Ok(ProveAggregationData {
        proof,
        quote,
        aggregation_hash,
    })
}

/// Verify that every sub-proof shares the same signer instance and that every
/// signature recovers cleanly to that instance.
///
/// # Errors
///
/// Returns an error if the list is empty, any proof is malformed, any signature
/// fails to recover the expected signer, or proofs disagree on the signer.
fn verify_sub_proofs(sub_proofs: &[(Vec<u8>, B256)]) -> Result<Address> {
    if sub_proofs.is_empty() {
        return Err(anyhow!("No sub-proofs provided for aggregation"));
    }

    let first_proof = TdxProof::from_bytes(&sub_proofs[0].0)?;
    let expected_instance = first_proof.public_key();

    for (i, (proof_bytes, input_hash)) in sub_proofs.iter().enumerate() {
        let tdx_proof = TdxProof::from_bytes(proof_bytes)?;
        let instance = tdx_proof.public_key();

        if instance != expected_instance {
            return Err(anyhow!(
                "Shasta aggregation does not allow key rotation: proof {i} has instance {instance}, expected {expected_instance}"
            ));
        }

        let signature = tdx_proof.signature();
        let recovered = recover_signer(&signature, input_hash)?;
        if recovered != expected_instance {
            return Err(anyhow!(
                "Proof {i} signature verification failed: expected signer {expected_instance}, got {recovered}"
            ));
        }
    }

    Ok(expected_instance)
}

#[cfg(test)]
mod tests {
    use super::{TDX_PROOF_SIZE, TdxProof, verify_sub_proofs};
    use crate::signature::{address_from_private_key, sign_message};
    use alloy_primitives::{Address, B256};
    use secp256k1::Secp256k1;

    fn signed_proof(
        secret: &secp256k1::SecretKey,
        instance_id: u32,
        input_hash: B256,
    ) -> (Vec<u8>, B256) {
        let address = address_from_private_key(secret);
        let signature = sign_message(secret, &input_hash).expect("sign");
        let proof = TdxProof::new(instance_id, &address, &signature).into_vec();
        (proof, input_hash)
    }

    #[test]
    fn from_bytes_rejects_short_buffer() {
        let err = TdxProof::from_bytes(&[0u8; TDX_PROOF_SIZE - 1]).expect_err("short");
        assert!(err.to_string().contains("Invalid proof size"));
    }

    #[test]
    fn from_bytes_rejects_long_buffer() {
        let err = TdxProof::from_bytes(&[0u8; TDX_PROOF_SIZE + 1]).expect_err("long");
        assert!(err.to_string().contains("Invalid proof size"));
    }

    #[test]
    fn proof_round_trip_preserves_fields() {
        let address = Address::repeat_byte(0xab);
        let signature = [0x42u8; 65];
        let proof = TdxProof::new(7, &address, &signature);
        let bytes = proof.into_vec();
        let parsed = TdxProof::from_bytes(&bytes).expect("parse");

        assert_eq!(parsed.instance_id(), 7);
        assert_eq!(parsed.public_key(), address);
        assert_eq!(parsed.signature(), signature);
    }

    #[test]
    fn verify_sub_proofs_rejects_empty() {
        let err = verify_sub_proofs(&[]).expect_err("empty");
        assert!(err.to_string().contains("No sub-proofs"));
    }

    #[test]
    fn verify_sub_proofs_accepts_consistent_signatures() {
        let secp = Secp256k1::new();
        let (secret, _) = secp.generate_keypair(&mut rand::thread_rng());
        let expected = address_from_private_key(&secret);

        let sub_proofs = vec![
            signed_proof(&secret, 1, B256::repeat_byte(0x11)),
            signed_proof(&secret, 1, B256::repeat_byte(0x22)),
        ];

        let instance = verify_sub_proofs(&sub_proofs).expect("verify");
        assert_eq!(instance, expected);
    }

    #[test]
    fn verify_sub_proofs_rejects_key_rotation() {
        let secp = Secp256k1::new();
        let (secret_a, _) = secp.generate_keypair(&mut rand::thread_rng());
        let (secret_b, _) = secp.generate_keypair(&mut rand::thread_rng());

        let sub_proofs = vec![
            signed_proof(&secret_a, 1, B256::repeat_byte(0x11)),
            signed_proof(&secret_b, 1, B256::repeat_byte(0x22)),
        ];

        let err = verify_sub_proofs(&sub_proofs).expect_err("rotation");
        assert!(
            err.to_string().contains("key rotation"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_sub_proofs_rejects_signature_against_wrong_hash() {
        let secp = Secp256k1::new();
        let (secret, _) = secp.generate_keypair(&mut rand::thread_rng());

        let (proof_bytes, _) = signed_proof(&secret, 1, B256::repeat_byte(0x11));
        let sub_proofs = vec![(proof_bytes, B256::repeat_byte(0x22))];

        let err = verify_sub_proofs(&sub_proofs).expect_err("bad sig");
        assert!(
            err.to_string().contains("signature verification failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_sub_proofs_rejects_malformed_proof_bytes() {
        let sub_proofs = vec![(vec![0u8; TDX_PROOF_SIZE - 1], B256::ZERO)];
        let err = verify_sub_proofs(&sub_proofs).expect_err("malformed");
        assert!(err.to_string().contains("Invalid proof size"));
    }
}
