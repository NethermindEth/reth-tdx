//! ECDSA signature utilities for the TDX bootstrap key.
//!
//! Uses the `secp256k1` crate's pre-allocated global context (enabled by the
//! `global-context` feature in `Cargo.toml`) so we don't reinit a context
//! table per call — the cost is meaningful under concurrent proof requests.

use alloy_primitives::{Address, B256, keccak256};
use anyhow::Result;
use secp256k1::{Message, PublicKey, SECP256K1, SecretKey, ecdsa::RecoverableSignature};

/// Derive an Ethereum address from a secp256k1 private key.
#[must_use]
pub fn address_from_private_key(private_key: &SecretKey) -> Address {
    let public_key = PublicKey::from_secret_key(SECP256K1, private_key);
    public_key_to_address(&public_key)
}

/// Convert a secp256k1 public key to an Ethereum address.
fn public_key_to_address(public_key: &PublicKey) -> Address {
    let hash = keccak256(&public_key.serialize_uncompressed()[1..]);
    Address::from_slice(&hash[12..])
}

/// Sign a 32-byte hash with a secp256k1 private key.
///
/// Returns a 65-byte Ethereum-compatible signature (r || s || v) where
/// v = recovery_id + 27.
///
/// # Errors
///
/// Returns an error if the message digest is invalid.
pub fn sign_message(private_key: &SecretKey, hash: &B256) -> Result<[u8; 65]> {
    let message = Message::from_digest_slice(hash.as_slice())?;
    let sig = SECP256K1.sign_ecdsa_recoverable(&message, private_key);

    let (recovery_id, sig_bytes) = sig.serialize_compact();
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&sig_bytes);
    signature[64] = u8::try_from(i32::from(recovery_id) + 27)
        .map_err(|_| anyhow::anyhow!("invalid recovery id value"))?;

    Ok(signature)
}

/// Recover the signer address from a 65-byte Ethereum signature and a message
/// hash.
///
/// # Errors
///
/// Returns an error if the recovery ID or signature is invalid.
pub fn recover_signer(sig: &[u8; 65], msg: &B256) -> Result<Address> {
    let recovery_id = secp256k1::ecdsa::RecoveryId::try_from(i32::from(sig[64]) - 27)?;
    let sig = RecoverableSignature::from_compact(&sig[..64], recovery_id)?;

    let message = Message::from_digest_slice(msg.as_slice())?;
    let public_key = SECP256K1.recover_ecdsa(&message, &sig)?;

    Ok(public_key_to_address(&public_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_recover_round_trip() {
        let (secret_key, _) = SECP256K1.generate_keypair(&mut rand::thread_rng());
        let expected_address = address_from_private_key(&secret_key);
        let hash = keccak256(b"test message");

        let signature = sign_message(&secret_key, &hash).expect("sign");
        let recovered = recover_signer(&signature, &hash).expect("recover");

        assert_eq!(recovered, expected_address);
    }
}
