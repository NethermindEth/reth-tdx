//! Persistent state for the TDX prover: bootstrap data + private key.
//!
//! Layout under [`config_dir()`] (default: `$HOME/.config/reth-tdx/`):
//!
//! ```text
//! reth-tdx/
//! ├── bootstrap.json          # public attestation record (camelCase keys)
//! └── secrets/
//!     └── priv.key            # 32-byte raw secp256k1 secret (mode 0600)
//! ```
//!
//! `config_dir()` accepts an explicit `home` override (via
//! [`crate::Config::home`]) so non-root systemd units can pin the directory
//! instead of relying on `$HOME`.

use std::{fs, path::PathBuf};

use alloy_primitives::Address;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

/// Persistent bootstrap record. Written once at first boot and read by the
/// `/bootstrap` HTTP handler.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapData {
    /// One of `tdx`, `azure`, `gcp`, `simulator`.
    pub issuer_type: String,
    /// Hex-encoded bootstrap public key (instance address).
    pub public_key: String,
    /// Hex-encoded TDX attestation quote.
    pub quote: String,
    /// Hex-encoded 32-byte random nonce used to derive the attestation
    /// extraData.
    pub nonce: String,
    /// Issuer-specific metadata (e.g. PCRs for Azure vTPM).
    pub metadata: serde_json::Value,
}

/// Resolve the on-disk reth-tdx directory, creating it if necessary.
///
/// `home_override` (from `--home` / `RETH_TDX_HOME`) takes precedence over
/// `$HOME` so the directory is deterministic when the binary runs as a
/// dedicated systemd user with no `$HOME` set.
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined or the directory
/// cannot be created.
pub fn config_dir(home_override: Option<&str>) -> Result<PathBuf> {
    let home = match home_override {
        Some(path) => PathBuf::from(path),
        None => dirs::home_dir().ok_or_else(|| anyhow!("Failed to get home directory"))?,
    };
    let dir = home.join(".config").join("reth-tdx");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Check whether both the bootstrap record and the private key exist on disk.
///
/// # Errors
///
/// Returns an error if the config directory cannot be resolved.
pub fn bootstrap_exists(home_override: Option<&str>) -> Result<bool> {
    let dir = config_dir(home_override)?;
    Ok(dir.join("bootstrap.json").exists() && dir.join("secrets").join("priv.key").exists())
}

/// Check whether the public bootstrap record (`bootstrap.json`) exists.
///
/// Unlike [`bootstrap_exists`], does not require the private key — useful when
/// only the public attestation record is needed (e.g. the `GET /bootstrap`
/// HTTP endpoint, which must serve while the prover is running but not let
/// callers exfiltrate the key).
///
/// # Errors
///
/// Returns an error if the config directory cannot be resolved.
pub fn bootstrap_record_exists(home_override: Option<&str>) -> Result<bool> {
    let dir = config_dir(home_override)?;
    Ok(dir.join("bootstrap.json").exists())
}

/// Generate a new secp256k1 private key and persist it.
///
/// # Errors
///
/// Returns an error if the key file cannot be written.
pub fn generate_private_key(home_override: Option<&str>) -> Result<secp256k1::SecretKey> {
    let secp = secp256k1::Secp256k1::new();
    let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
    save_private_key(home_override, &secret_key)?;
    Ok(secret_key)
}

/// Save a private key with restricted permissions (Unix 0600).
///
/// The file is created with 0600 from the start so the key bytes are never on
/// disk under the default umask before being narrowed.
fn save_private_key(home_override: Option<&str>, key: &secp256k1::SecretKey) -> Result<()> {
    let dir = config_dir(home_override)?;
    let secrets_dir = dir.join("secrets");
    fs::create_dir_all(&secrets_dir)?;

    let key_file = secrets_dir.join("priv.key");

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&key_file)?;
        file.write_all(&key.secret_bytes())?;
    }

    #[cfg(not(unix))]
    {
        fs::write(&key_file, key.secret_bytes())?;
    }

    Ok(())
}

/// Load the private key from disk.
///
/// # Errors
///
/// Returns an error if the key file cannot be read or contains invalid data.
pub fn load_private_key(home_override: Option<&str>) -> Result<secp256k1::SecretKey> {
    let dir = config_dir(home_override)?;
    let key_file = dir.join("secrets").join("priv.key");
    let key_bytes = fs::read(&key_file)
        .with_context(|| format!("Failed to read private key from {}", key_file.display()))?;
    secp256k1::SecretKey::from_slice(&key_bytes).map_err(|e| anyhow!("Invalid private key: {e}"))
}

/// Read the bootstrap record from disk.
///
/// # Errors
///
/// Returns an error if the file cannot be read or contains invalid JSON.
pub fn read_bootstrap(home_override: Option<&str>) -> Result<BootstrapData> {
    let dir = config_dir(home_override)?;
    let path = dir.join("bootstrap.json");
    let raw = fs::read_to_string(&path)?;
    serde_json::from_str(&raw).map_err(|e| anyhow!("Failed to parse bootstrap data: {e}"))
}

/// Write the bootstrap record to disk.
///
/// # Errors
///
/// Returns an error if the file cannot be written.
pub fn write_bootstrap(
    home_override: Option<&str>,
    issuer_type: &str,
    quote: &[u8],
    public_key: &Address,
    nonce: &[u8],
    metadata: serde_json::Value,
) -> Result<()> {
    let dir = config_dir(home_override)?;
    let path = dir.join("bootstrap.json");

    let data = BootstrapData {
        issuer_type: issuer_type.to_string(),
        public_key: public_key.to_string(),
        quote: hex::encode(quote),
        nonce: hex::encode(nonce),
        metadata,
    };
    fs::write(&path, serde_json::to_string_pretty(&data)?)?;
    Ok(())
}

/// The set of issuer strings the tdxs daemon may return for a TDX deployment.
/// All four map to the same on-the-wire format (the on-chain
/// `AzureTdxVerifier` distinguishes between Azure vTPM and bare TDX inside its
/// own decoder, not via this string).
pub const SUPPORTED_ISSUER_TYPES: &[&str] = &["tdx", "azure", "gcp", "simulator"];

/// Validate that an issuer string is one the tdxs daemon emits.
///
/// # Errors
///
/// Returns an error if the issuer is not recognised.
pub fn validate_issuer(issuer: &str) -> Result<()> {
    if SUPPORTED_ISSUER_TYPES.contains(&issuer) {
        Ok(())
    } else {
        Err(anyhow!(
            "Unsupported tdxs issuer '{issuer}' — expected one of {:?}",
            SUPPORTED_ISSUER_TYPES
        ))
    }
}
