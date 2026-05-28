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

/// Resolve the on-disk reth-tdx directory without creating it. Use for
/// read-only operations.
///
/// `home_override` (from `--home` / `RETH_TDX_HOME`) takes precedence over
/// `$HOME` so the directory is deterministic when the binary runs as a
/// dedicated systemd user with no `$HOME` set.
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined.
pub fn config_dir(home_override: Option<&str>) -> Result<PathBuf> {
    let home = match home_override {
        Some(path) => PathBuf::from(path),
        None => dirs::home_dir().ok_or_else(|| anyhow!("Failed to get home directory"))?,
    };
    Ok(home.join(".config").join("reth-tdx"))
}

/// Resolve the on-disk reth-tdx directory, creating it (and any missing
/// parents) if necessary. Use for write paths.
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined or the directory
/// cannot be created.
fn config_dir_for_write(home_override: Option<&str>) -> Result<PathBuf> {
    let dir = config_dir(home_override)?;
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
    let dir = config_dir_for_write(home_override)?;
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

/// Write the bootstrap record to disk atomically (write-to-temp + rename) so a
/// crash mid-write cannot leave a half-written `bootstrap.json` that fails to
/// parse on the next start.
///
/// # Errors
///
/// Returns an error if the file cannot be written or renamed into place.
pub fn write_bootstrap(
    home_override: Option<&str>,
    issuer_type: &str,
    quote: &[u8],
    public_key: &Address,
    nonce: &[u8],
    metadata: serde_json::Value,
) -> Result<()> {
    let dir = config_dir_for_write(home_override)?;
    let path = dir.join("bootstrap.json");
    let tmp = dir.join("bootstrap.json.tmp");

    let data = BootstrapData {
        issuer_type: issuer_type.to_string(),
        public_key: public_key.to_string(),
        quote: hex::encode(quote),
        nonce: hex::encode(nonce),
        metadata,
    };
    let serialized = serde_json::to_string_pretty(&data)?;
    fs::write(&tmp, serialized).with_context(|| format!("failed to write {}", tmp.display()))?;
    fs::rename(&tmp, &path)
        .with_context(|| format!("failed to rename {} -> {}", tmp.display(), path.display()))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_address() -> Address {
        Address::repeat_byte(0xab)
    }

    #[test]
    fn validate_issuer_accepts_known_types() {
        for issuer in SUPPORTED_ISSUER_TYPES {
            validate_issuer(issuer).unwrap_or_else(|_| panic!("should accept {issuer}"));
        }
    }

    #[test]
    fn validate_issuer_rejects_unknown() {
        let err = validate_issuer("aws-nitro").expect_err("should reject unknown issuer");
        assert!(err.to_string().contains("aws-nitro"));
    }

    #[test]
    fn config_dir_does_not_create() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        let dir = config_dir(Some(&home)).unwrap();
        assert!(
            !dir.exists(),
            "read-only config_dir should not create the directory"
        );
    }

    #[test]
    fn write_bootstrap_round_trips_via_read_bootstrap() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        let address = sample_address();
        let metadata = serde_json::json!({"pcr0": "deadbeef"});

        write_bootstrap(
            Some(&home),
            "tdx",
            &[0x01, 0x02, 0x03],
            &address,
            &[0xaa; 32],
            metadata.clone(),
        )
        .unwrap();

        let data = read_bootstrap(Some(&home)).unwrap();
        assert_eq!(data.issuer_type, "tdx");
        assert_eq!(data.public_key, address.to_string());
        assert_eq!(data.quote, "010203");
        assert_eq!(data.nonce, hex::encode([0xaa; 32]));
        assert_eq!(data.metadata, metadata);
    }

    #[test]
    fn write_bootstrap_is_atomic_no_tmp_remains() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        write_bootstrap(
            Some(&home),
            "tdx",
            &[0u8; 4],
            &sample_address(),
            &[0u8; 32],
            serde_json::json!({}),
        )
        .unwrap();
        let tmp_path = tmp
            .path()
            .join(".config")
            .join("reth-tdx")
            .join("bootstrap.json.tmp");
        assert!(
            !tmp_path.exists(),
            "atomic write must leave no .tmp behind after rename"
        );
    }

    #[test]
    fn bootstrap_record_exists_detects_only_bootstrap_json() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        assert!(!bootstrap_record_exists(Some(&home)).unwrap());
        write_bootstrap(
            Some(&home),
            "tdx",
            &[0u8; 4],
            &sample_address(),
            &[0u8; 32],
            serde_json::json!({}),
        )
        .unwrap();
        assert!(bootstrap_record_exists(Some(&home)).unwrap());
        // priv.key absent → full bootstrap NOT considered complete.
        assert!(!bootstrap_exists(Some(&home)).unwrap());
    }

    #[test]
    fn generate_private_key_and_round_trip_load() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        let key = generate_private_key(Some(&home)).unwrap();
        let loaded = load_private_key(Some(&home)).unwrap();
        assert_eq!(key.secret_bytes(), loaded.secret_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn private_key_file_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        generate_private_key(Some(&home)).unwrap();
        let key_path = tmp
            .path()
            .join(".config")
            .join("reth-tdx")
            .join("secrets")
            .join("priv.key");
        let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "priv.key must be created with 0600");
    }

    #[test]
    fn bootstrap_exists_requires_both_files() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().to_string_lossy().to_string();
        // Generate only the private key → bootstrap is incomplete.
        generate_private_key(Some(&home)).unwrap();
        assert!(!bootstrap_exists(Some(&home)).unwrap());
        write_bootstrap(
            Some(&home),
            "tdx",
            &[0u8; 4],
            &sample_address(),
            &[0u8; 32],
            serde_json::json!({}),
        )
        .unwrap();
        assert!(bootstrap_exists(Some(&home)).unwrap());
    }
}
