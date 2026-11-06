//! Crypto layer: Argon2id key derivation + AES-256-GCM authenticated encryption,
//! plus serialization of the profile file format.
//!
//! File format (v1):
//! ```text
//! magic "ENVPOUCH"(8B) | version(1B) | salt(16B) | argon2 params m/t/p(12B, LE)
//! | nonce(12B) | var_count(4B, LE) | updated_at(8B, LE) | AES-256-GCM ciphertext
//! ```
//! The header (everything before the ciphertext) is used as GCM AAD, so tampering
//! with any header field fails decryption. var_count / updated_at are plaintext
//! metadata so `list` can display them without asking for a password.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use getrandom::getrandom;
use zeroize::Zeroizing;

/// On-disk format v1 magic. Frozen now that the format is defined: changing it
/// (or its length) breaks decryption of every existing profile, so from here
/// on it only changes together with a format version bump.
pub const MAGIC: &[u8; 8] = b"ENVPOUCH";
pub const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
/// GCM authentication tag length (fixed 128 bits)
const TAG_LEN: usize = 16;
/// Header size: magic + version(1) + salt(16) + kdf params(12) + nonce(12) + var_count(4) + updated_at(8)
pub const HEADER_LEN: usize = MAGIC.len() + 1 + SALT_LEN + 12 + NONCE_LEN + 4 + 8;

/// OWASP-recommended Argon2id parameters: m=19 MiB, t=2, p=1
pub const DEFAULT_M_COST: u32 = 19 * 1024;
pub const DEFAULT_T_COST: u32 = 2;
pub const DEFAULT_P_COST: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost (KiB)
    pub m_cost: u32,
    /// Number of iterations
    pub t_cost: u32,
    /// Degree of parallelism
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

/// A password-derived key plus the salt/params it was derived with.
///
/// Kept across a decrypt→re-encrypt cycle so mutating commands (set/unset/
/// edit/merge) run Argon2 once instead of twice: re-encryption reuses the
/// key and only draws a fresh nonce. The profile file keeps its salt; GCM
/// only requires nonce uniqueness per key, and nonces are 96-bit random
/// per write, so reuse is safe well beyond any CLI's write count.
pub struct DerivedKey {
    key: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
    params: KdfParams,
}

impl DerivedKey {
    /// Derive from a password with a fresh random salt (new profiles,
    /// password changes).
    pub fn fresh(password: &str) -> Result<Self> {
        let params = KdfParams::default();
        validate_kdf_params(params.m_cost, params.t_cost, params.p_cost)?;
        let mut salt = [0u8; SALT_LEN];
        getrandom(&mut salt).map_err(|e| anyhow!("failed to generate random salt: {e}"))?;
        let key = derive_key(password, &salt, params)?;
        Ok(Self { key, salt, params })
    }
}

/// Plaintext metadata that can be read without decryption
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileMeta {
    pub var_count: u32,
    pub updated_at: u64,
}

pub struct Decrypted {
    pub plaintext: Zeroizing<Vec<u8>>,
    /// Used by tests to verify metadata roundtrip
    #[allow(dead_code)]
    pub meta: FileMeta,
}

/// Debug impl never prints plaintext, to avoid leaking secrets to logs
impl std::fmt::Debug for Decrypted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decrypted")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

fn validate_kdf_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<()> {
    // Upper bounds prevent a maliciously crafted file from exhausting
    // memory/CPU during decryption
    const MAX_M_COST: u32 = 1_048_576; // 1 GiB
    if !(8192..=MAX_M_COST).contains(&m_cost)
        || !(1..=16).contains(&t_cost)
        || !(1..=8).contains(&p_cost)
    {
        bail!("KDF parameters out of allowed range (file may be tampered with)");
    }
    Ok(())
}

fn derive_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| anyhow!("invalid KDF parameters: {e}"))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    a2.hash_password_into(password.as_bytes(), salt, &mut key[..])
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Encrypt with an already-derived key: the profile keeps its salt/params
/// and gets a fresh random nonce.
pub fn encrypt_derived(plaintext: &[u8], derived: &DerivedKey, meta: FileMeta) -> Result<Vec<u8>> {
    validate_kdf_params(
        derived.params.m_cost,
        derived.params.t_cost,
        derived.params.p_cost,
    )?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VERSION);
    header.extend_from_slice(&derived.salt);
    header.extend_from_slice(&derived.params.m_cost.to_le_bytes());
    header.extend_from_slice(&derived.params.t_cost.to_le_bytes());
    header.extend_from_slice(&derived.params.p_cost.to_le_bytes());

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived.key[..]));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    header.extend_from_slice(nonce.as_slice());
    header.extend_from_slice(&meta.var_count.to_le_bytes());
    header.extend_from_slice(&meta.updated_at.to_le_bytes());
    debug_assert_eq!(header.len(), HEADER_LEN);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|e| anyhow!("encryption failed: {e}"))?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

/// Decrypt profile file bytes. Returns an error on wrong password or tampered content.
pub fn decrypt(blob: &[u8], password: &str) -> Result<Decrypted> {
    Ok(decrypt_derived(blob, password)?.0)
}

/// Decrypt and also return the derived key, so a verified password can
/// re-encrypt the profile without a second KDF pass.
pub fn decrypt_derived(blob: &[u8], password: &str) -> Result<(Decrypted, DerivedKey)> {
    if blob.len() < HEADER_LEN + TAG_LEN {
        bail!("file too small to be a valid envpouch profile");
    }
    if &blob[..MAGIC.len()] != MAGIC {
        bail!("not a valid envpouch profile (magic mismatch)");
    }
    if blob[MAGIC.len()] != FORMAT_VERSION {
        bail!(
            "unsupported profile file version: {} (supported: {})",
            blob[MAGIC.len()],
            FORMAT_VERSION
        );
    }

    let mut off = MAGIC.len() + 1;
    let salt: [u8; SALT_LEN] = blob[off..off + SALT_LEN].try_into().unwrap();
    off += SALT_LEN;
    let m_cost = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap());
    off += 4;
    let t_cost = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap());
    off += 4;
    let p_cost = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap());
    off += 4;
    let nonce: [u8; NONCE_LEN] = blob[off..off + NONCE_LEN].try_into().unwrap();
    off += NONCE_LEN;
    let var_count = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap());
    off += 4;
    let updated_at = u64::from_le_bytes(blob[off..off + 8].try_into().unwrap());
    debug_assert_eq!(off + 8, HEADER_LEN);

    validate_kdf_params(m_cost, t_cost, p_cost)?;
    let params = KdfParams {
        m_cost,
        t_cost,
        p_cost,
    };

    let (header, ciphertext) = blob.split_at(HEADER_LEN);
    let key = derive_key(password, &salt, params)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key[..]));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| anyhow!("wrong password or profile file is corrupted"))?;

    Ok((
        Decrypted {
            plaintext: Zeroizing::new(plaintext),
            meta: FileMeta {
                var_count,
                updated_at,
            },
        },
        DerivedKey { key, salt, params },
    ))
}

/// Parse only the plaintext header metadata (used by `list`, no password needed).
pub fn read_meta(blob: &[u8]) -> Result<FileMeta> {
    if blob.len() < HEADER_LEN || &blob[..MAGIC.len()] != MAGIC {
        bail!("not a valid envpouch profile");
    }
    if blob[MAGIC.len()] != FORMAT_VERSION {
        bail!("unsupported profile file version: {}", blob[MAGIC.len()]);
    }
    let off = MAGIC.len() + 1 + SALT_LEN + 12 + NONCE_LEN;
    let var_count = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap());
    let updated_at = u64::from_le_bytes(blob[off + 4..off + 12].try_into().unwrap());
    Ok(FileMeta {
        var_count,
        updated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Password-based encryption for tests: fresh key + `encrypt_derived`
    /// (the removed public wrapper was exactly this composition).
    fn encrypt(plaintext: &[u8], password: &str, meta: FileMeta) -> Result<Vec<u8>> {
        encrypt_derived(plaintext, &DerivedKey::fresh(password)?, meta)
    }

    fn sample_meta() -> FileMeta {
        FileMeta {
            var_count: 2,
            updated_at: 1_700_000_000,
        }
    }

    #[test]
    fn roundtrip() {
        let data = b"hello secrets";
        let blob = encrypt(data, "correct horse", sample_meta()).unwrap();
        let dec = decrypt(&blob, "correct horse").unwrap();
        assert_eq!(dec.plaintext.as_slice(), data);
        assert_eq!(dec.meta, sample_meta());
    }

    #[test]
    fn wrong_password_rejected() {
        let blob = encrypt(b"x", "right-password", sample_meta()).unwrap();
        let err = decrypt(&blob, "wrong-password").unwrap_err();
        assert!(err.to_string().contains("wrong password"));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut blob = encrypt(b"x", "pw123456", sample_meta()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(decrypt(&blob, "pw123456").is_err());
    }

    #[test]
    fn tampered_header_rejected() {
        let mut blob = encrypt(b"x", "pw123456", sample_meta()).unwrap();
        // salt region (covered by AAD)
        blob[MAGIC.len() + 1] ^= 1;
        assert!(decrypt(&blob, "pw123456").is_err());
    }

    #[test]
    fn bad_magic_rejected() {
        let mut blob = encrypt(b"x", "pw123456", sample_meta()).unwrap();
        blob[0] = b'X';
        assert!(decrypt(&blob, "pw123456").is_err());
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut blob = encrypt(b"x", "pw123456", sample_meta()).unwrap();
        blob[MAGIC.len()] = 99;
        assert!(decrypt(&blob, "pw123456").is_err());
    }

    #[test]
    fn meta_readable_without_password() {
        let blob = encrypt(b"x", "pw123456", sample_meta()).unwrap();
        assert_eq!(read_meta(&blob).unwrap(), sample_meta());
    }

    #[test]
    fn truncated_file_rejected() {
        let blob = encrypt(b"x", "pw123456", sample_meta()).unwrap();
        assert!(decrypt(&blob[..HEADER_LEN], "pw123456").is_err());
    }

    #[test]
    fn forged_kdf_params_rejected() {
        let mut blob = encrypt(b"x", "pw123456", sample_meta()).unwrap();
        // Set the m_cost field beyond the allowed range (params check fires
        // before AAD verification does)
        let m_off = MAGIC.len() + 1 + SALT_LEN;
        blob[m_off..m_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decrypt(&blob, "pw123456").is_err());
    }

    #[test]
    fn derived_key_roundtrip_preserves_salt_and_rotates_nonce() {
        let blob1 = encrypt(b"old payload", "pw123456", sample_meta()).unwrap();
        let (_, derived) = decrypt_derived(&blob1, "pw123456").unwrap();
        let meta2 = FileMeta {
            var_count: 7,
            updated_at: 99,
        };
        let blob2 = encrypt_derived(b"new payload", &derived, meta2).unwrap();

        // salt + KDF params region is preserved; only the nonce is fresh
        let stable = MAGIC.len() + 1..MAGIC.len() + 1 + SALT_LEN + 12;
        assert_eq!(blob1[stable.clone()], blob2[stable]);
        let dec2 = decrypt(&blob2, "pw123456").unwrap();
        assert_eq!(dec2.plaintext.as_slice(), b"new payload");
        assert_eq!(dec2.meta, meta2);

        // a second write under the same key draws a new nonce/ciphertext
        let blob3 = encrypt_derived(b"new payload", &derived, meta2).unwrap();
        // nonce sits between the KDF params and var_count
        let nonce = HEADER_LEN - 24..HEADER_LEN - 12;
        assert_ne!(blob2[nonce.clone()], blob3[nonce]);
        assert_ne!(blob2[HEADER_LEN..], blob3[HEADER_LEN..]);
    }
}
