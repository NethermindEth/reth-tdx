//! Bootstrap orchestration: generate a TDX-bound key, request the attestation
//! quote, persist both, and emit the bootstrap record.
//!
//! Idempotent — if a bootstrap record already exists on disk, it is returned
//! as-is.

use std::str::FromStr;

use alloy_primitives::Address;
use anyhow::{Context, Result, anyhow};
use serde_json::Value;
use tracing::info;

use crate::{
    attestation, persistence,
    proof::{generate_tdx_quote_from_public_key, get_tdx_metadata},
    protocol::BootstrapResponse,
    signature::address_from_private_key,
};

/// Ensure the prover has been bootstrapped on disk, then return the public
/// bootstrap record.
///
/// # Errors
///
/// Returns an error if the tdxs daemon is unreachable, the attestation quote
/// cannot be generated, or the bootstrap files cannot be written / read.
pub async fn bootstrap(
    home_override: Option<&str>,
    socket_path: &str,
) -> Result<BootstrapResponse> {
    if persistence::bootstrap_exists(home_override)? {
        info!("reth-tdx already bootstrapped — reusing existing key");
        return load_bootstrap_response(home_override);
    }

    info!("Bootstrapping reth-tdx prover...");

    let metadata = get_tdx_metadata(socket_path)
        .await
        .context("failed to fetch tdxs daemon metadata")?;
    persistence::validate_issuer(&metadata.issuer_type)?;

    let private_key = persistence::generate_private_key(home_override)
        .context("failed to generate / persist bootstrap key")?;
    let address = address_from_private_key(&private_key);
    info!("Generated reth-tdx prover address: {address}");

    let (quote, nonce) = generate_tdx_quote_from_public_key(socket_path, &address)
        .await
        .context("failed to request TDX attestation quote")?;
    info!("TDX bootstrap quote generated ({} bytes)", quote.len());

    persistence::write_bootstrap(
        home_override,
        &metadata.issuer_type,
        &quote,
        &address,
        &nonce,
        metadata.metadata.clone(),
    )
    .context("failed to persist bootstrap record")?;

    info!("reth-tdx bootstrap complete");
    load_bootstrap_response(home_override)
}

/// Read the bootstrap record from disk and project it to the public response
/// shape served by `GET /bootstrap`.
///
/// # Errors
///
/// Returns an error if the bootstrap file is missing or malformed.
pub fn load_bootstrap_response(home_override: Option<&str>) -> Result<BootstrapResponse> {
    let data =
        persistence::read_bootstrap(home_override).context("failed to read bootstrap record")?;
    Ok(BootstrapResponse {
        issuer_type: data.issuer_type,
        public_key: data.public_key,
        quote: data.quote,
        nonce: data.nonce,
        metadata: data.metadata,
    })
}

/// Sanity-check that the tdxs daemon responds.
///
/// # Errors
///
/// Returns an error if the daemon's `metadata` round-trip fails.
pub async fn ping_attestation(socket_path: &str) -> Result<Value> {
    let metadata = attestation::metadata(socket_path)
        .await
        .context("tdxs daemon ping failed")?;
    Ok(serde_json::json!({
        "issuer_type": metadata.issuer_type,
        "metadata": metadata.metadata,
    }))
}

/// Verify the on-disk bootstrap key recovers to the address recorded in
/// `bootstrap.json`. Used by `reth-tdx check` to flag tampered or partially
/// rotated state.
///
/// # Errors
///
/// Returns an error if either file is missing or the addresses disagree.
pub fn verify_disk_consistency(home_override: Option<&str>) -> Result<()> {
    let record = persistence::read_bootstrap(home_override)?;
    let key = persistence::load_private_key(home_override)?;
    let actual = address_from_private_key(&key);
    let recorded = Address::from_str(&record.public_key).with_context(|| {
        format!(
            "bootstrap.json public_key is not a valid Ethereum address: {}",
            record.public_key
        )
    })?;
    if actual != recorded {
        return Err(anyhow!(
            "bootstrap key/address mismatch: priv.key recovers to {actual} but bootstrap.json records {recorded}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence;
    use tempfile::TempDir;

    #[test]
    fn verify_disk_consistency_accepts_matching_pair() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        let key = persistence::generate_private_key(Some(&home)).unwrap();
        let address = address_from_private_key(&key);
        persistence::write_bootstrap(
            Some(&home),
            "tdx",
            &[0u8; 4],
            &address,
            &[0u8; 32],
            serde_json::json!({}),
        )
        .unwrap();

        verify_disk_consistency(Some(&home)).expect("matching key+record should be consistent");
    }

    #[test]
    fn verify_disk_consistency_rejects_mismatched_address() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        // Generate one key, but record a *different* address in bootstrap.json.
        persistence::generate_private_key(Some(&home)).unwrap();
        let other = Address::repeat_byte(0x33);
        persistence::write_bootstrap(
            Some(&home),
            "tdx",
            &[0u8; 4],
            &other,
            &[0u8; 32],
            serde_json::json!({}),
        )
        .unwrap();

        let err = verify_disk_consistency(Some(&home)).expect_err("mismatch should fail");
        assert!(
            err.to_string().contains("mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_disk_consistency_rejects_malformed_public_key() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        let key = persistence::generate_private_key(Some(&home)).unwrap();
        let address = address_from_private_key(&key);
        persistence::write_bootstrap(
            Some(&home),
            "tdx",
            &[0u8; 4],
            &address,
            &[0u8; 32],
            serde_json::json!({}),
        )
        .unwrap();

        // Corrupt the bootstrap.json public_key.
        let path = tmp
            .path()
            .join(".config")
            .join("reth-tdx")
            .join("bootstrap.json");
        let mut record: persistence::BootstrapData =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        record.public_key = "not-an-address".to_string();
        std::fs::write(&path, serde_json::to_string_pretty(&record).unwrap()).unwrap();

        let err = verify_disk_consistency(Some(&home)).expect_err("bad address should fail");
        assert!(
            err.to_string().contains("not a valid Ethereum address"),
            "unexpected error: {err}"
        );
    }
}
