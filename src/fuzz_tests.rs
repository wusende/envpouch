//! Deterministic fuzz/robustness tests (no external fuzzer required).
//!
//! Feeds generated garbage — random bytes, truncations, bit flips, random
//! Unicode — into every pure input surface and asserts the only acceptable
//! outcomes: `Ok` or a clean `Err`. **Any panic (unwrap, index OOB, integer
//! overflow in debug, dotenvy internals) fails the suite.**
//!
//! Reproducible: a fixed-seed xorshift PRNG, so a failure can be replayed.
//!
//! (The module is already gated by `#[cfg(test)]` in main.rs; no inner
//! `#![cfg(test)]` — clippy flags the duplication.)

use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::crypto;
use crate::envfile::{self, EnvVars};
use crate::mask;
use crate::profile;
use std::collections::BTreeMap;

/// xorshift64*: tiny deterministic PRNG, seeded per test.
struct XorShift(u64);

impl XorShift {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Assert `f` does not panic; map the result to Ok/Err without unwrapping it.
fn no_panic<T, F: FnOnce() -> T>(f: F) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|p| {
        let msg = p
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "opaque panic payload".to_string());
        format!("PANIC: {msg}")
    })
}

const NUL: char = '\0';

/// Characters fed into string-typed surfaces.
const CHARSET: &[char] = &[
    'a', 'Z', '0', '9', '_', '-', '.', '/', ':', '=', ',', '~', '@', '%', '+', ' ', '\t', '\n',
    '\r', '\'', '"', '\\', '$', '#', '中', 'é', '😀', '\u{7f}', '\u{a0}', NUL,
];

fn rand_string(rng: &mut XorShift, max_len: usize) -> String {
    let len = rng.below(max_len + 1);
    (0..len)
        .map(|_| CHARSET[rng.below(CHARSET.len())])
        .collect()
}

fn rand_bytes(rng: &mut XorShift, max_len: usize) -> Vec<u8> {
    let len = rng.below(max_len + 1);
    (0..len).map(|_| (rng.next() & 0xff) as u8).collect()
}

// ---------------------------------------------------------------------------
// crypto surfaces
// ---------------------------------------------------------------------------

/// A profile blob whose header is valid and whose Argon2 params are the
/// cheapest allowed, so the derive step inside decrypt stays fast while the
/// GCM/AAD paths are still exercised.
fn craft_fast_blob(rng: &mut XorShift, body_len: usize) -> Vec<u8> {
    let mut b = Vec::with_capacity(crypto::HEADER_LEN + body_len);
    b.extend_from_slice(crypto::MAGIC);
    b.push(crypto::FORMAT_VERSION);
    b.extend_from_slice(&rand_bytes(rng, 16)); // salt
    b.extend_from_slice(&8192u32.to_le_bytes()); // m_cost (minimum)
    b.extend_from_slice(&1u32.to_le_bytes()); // t_cost
    b.extend_from_slice(&1u32.to_le_bytes()); // p_cost
    b.extend_from_slice(&rand_bytes(rng, 12)); // nonce
    b.extend_from_slice(&(rng.next() as u32).to_le_bytes()); // var_count
    b.extend_from_slice(&rng.next().to_le_bytes()); // updated_at
    b.extend_from_slice(&rand_bytes(rng, body_len)); // "ciphertext"
    b
}

#[test]
fn fuzz_decrypt_never_panics() {
    let mut rng = XorShift::new(0xDEAD_BEEF);
    let pw = "fuzz-password-1";

    // 1) pure random blobs — most rejected at the magic check
    for _ in 0..300 {
        let blob = rand_bytes(&mut rng, crypto::HEADER_LEN + 64);
        let r = no_panic(|| crypto::decrypt(&blob, pw));
        assert!(
            r.is_ok(),
            "decrypt panicked on random blob: {}",
            r.unwrap_err()
        );
    }

    // 2) crafted valid-header blobs (fast KDF) with random bodies — exercises
    //    derive + AAD + GCM verification
    for _ in 0..60 {
        let body_len = rng.below(96);
        let blob = craft_fast_blob(&mut rng, body_len);
        let r = no_panic(|| crypto::decrypt(&blob, pw));
        assert!(
            r.is_ok(),
            "decrypt panicked on crafted blob: {}",
            r.unwrap_err()
        );
    }

    // 3) bit flips in a valid-shape blob at every byte offset (mod 7 stride)
    let base = craft_fast_blob(&mut rng, 32);
    for off in (0..base.len()).step_by(7) {
        let mut blob = base.clone();
        blob[off] ^= 0x20;
        let r = no_panic(|| crypto::decrypt(&blob, pw));
        assert!(
            r.is_ok(),
            "decrypt panicked on bit flip at {off}: {}",
            r.unwrap_err()
        );
    }

    // 4) truncations at every length class
    for cut in [0, 1, 6, 7, 23, 35, 47, 59, 60, 75, 100] {
        let end = cut.min(base.len());
        let r = no_panic(|| crypto::decrypt(&base[..end], pw));
        assert!(
            r.is_ok(),
            "decrypt panicked on truncation to {end}: {}",
            r.unwrap_err()
        );
    }
}

#[test]
fn fuzz_read_meta_never_panics() {
    let mut rng = XorShift::new(0xCAFE_0001);
    for _ in 0..400 {
        let blob = rand_bytes(&mut rng, crypto::HEADER_LEN + 32);
        let r = no_panic(|| crypto::read_meta(&blob));
        assert!(r.is_ok(), "read_meta panicked: {}", r.unwrap_err());
    }
}

// ---------------------------------------------------------------------------
// envfile surfaces
// ---------------------------------------------------------------------------

#[test]
fn fuzz_parse_file_never_panics() {
    let mut rng = XorShift::new(0xABCD_1234);
    let dir: &'static tempfile::TempDir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let path = dir.path().join("fuzz.env");

    // 1) pure random bytes as .env content
    for i in 0..400 {
        let content = rand_bytes(&mut rng, 512);
        std::fs::write(&path, &content).unwrap();
        let r = no_panic(|| EnvVars::parse_file(&path));
        assert!(
            r.is_ok(),
            "parse_file panicked on iteration {i}: {}",
            r.unwrap_err()
        );
    }

    // 2) truncations of a valid file
    let valid = b"FOO=bar\nexport BAZ=\"multi\nline\"\nQUOTED='it is' # c\n";
    for cut in 0..valid.len() {
        std::fs::write(&path, &valid[..cut]).unwrap();
        let r = no_panic(|| EnvVars::parse_file(&path));
        assert!(
            r.is_ok(),
            "parse_file panicked on truncation {cut}: {}",
            r.unwrap_err()
        );
    }
}

/// Valid identifier keys with fuzzed values: export → re-import must be an
/// exact roundtrip (this is the contract behind `export`/`edit`/`show
/// --reveal`). Discovers quoting/escape gaps in `format_value` — e.g. raw
/// `\r`, stray quotes, dollar sequences.
#[test]
fn fuzz_env_text_roundtrip_exact() {
    let mut rng = XorShift::new(0xF00D_0002);
    let dir: &'static tempfile::TempDir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let path = dir.path().join("roundtrip.env");

    for i in 0..500 {
        // keys stay valid identifiers; values are fully fuzzed (except NUL,
        // which validate_key rejects at import by contract)
        let mut value: String = rand_string(&mut rng, 24)
            .chars()
            .filter(|c| *c != NUL)
            .collect();
        if rng.below(4) == 0 {
            // bias toward quote/dollar-heavy values
            value = format!("{}'\"${}\"", value, rand_string(&mut rng, 6));
        }
        let key = format!("K{}", i);
        let vars = EnvVars::from_map(BTreeMap::from([(key.clone(), value.clone())]));

        let text = vars.to_env_text();
        std::fs::write(&path, &text).unwrap();
        // no_panic yields Result<Result<EnvVars, _>, String> — unwrap both
        // layers: our own exported text must parse cleanly (a parse failure
        // is a roundtrip bug, not an acceptable outcome)
        let reparsed = match no_panic(|| EnvVars::parse_file(&path)) {
            Ok(Ok(v)) => v,
            Ok(Err(parse_err)) => {
                panic!("iteration {i}: exported text failed to parse {text:?}: {parse_err}")
            }
            Err(e) => panic!("iteration {i}: parse panicked on exported text {text:?}: {e}"),
        };
        let get = reparsed
            .iter()
            .find(|(k, _)| k.as_str() == key)
            .map(|(_, v)| v.clone());
        assert_eq!(
            get.as_deref(),
            Some(value.as_str()),
            "roundtrip mismatch for value {value:?} (exported as {:?})",
            text.trim()
        );
    }
}

#[test]
fn fuzz_validate_key_never_panics() {
    let mut rng = XorShift::new(0x5EED_0003);
    for _ in 0..1000 {
        let k = rand_string(&mut rng, 16);
        let v = rand_string(&mut rng, 16);
        let r = no_panic(|| envfile::validate_key(&k, &v));
        assert!(
            r.is_ok(),
            "validate_key panicked on {k:?}: {}",
            r.unwrap_err()
        );
    }
}

#[test]
fn fuzz_merge_invariants() {
    let mut rng = XorShift::new(0x5EED_0004);
    for _ in 0..300 {
        let mut a = BTreeMap::new();
        let mut b = BTreeMap::new();
        for i in 0..rng.below(6) {
            a.insert(format!("A{i}"), rand_string(&mut rng, 8));
        }
        for i in 0..rng.below(6) {
            b.insert(format!("B{i}"), rand_string(&mut rng, 8));
        }
        // ensure some overlap
        if !a.is_empty() && !b.is_empty() {
            let k = a.keys().next().unwrap().clone();
            b.insert(k, "overridden".to_string());
        }
        let mut base = EnvVars::from_map(a.clone());
        let incoming = EnvVars::from_map(b.clone());
        let (added, updated) = no_panic(|| base.merge(incoming)).unwrap();
        assert_eq!(added + updated, b.len());
        // every incoming key must be present afterwards with the incoming value
        for (k, v) in &b {
            let got = base
                .iter()
                .find(|(ka, _)| *ka == k)
                .map(|(_, vb)| vb.clone());
            assert_eq!(got.as_deref(), Some(v.as_str()), "merge lost key {k}");
        }
    }
}

// ---------------------------------------------------------------------------
// pure string surfaces
// ---------------------------------------------------------------------------

#[test]
fn fuzz_mask_never_panics() {
    let mut rng = XorShift::new(0x5EED_0005);
    for _ in 0..1000 {
        let s = rand_string(&mut rng, 32);
        let r = no_panic(|| mask::mask(&s));
        assert!(r.is_ok(), "mask panicked on {s:?}: {}", r.unwrap_err());
    }
}

#[test]
fn fuzz_validate_name_never_panics() {
    let mut rng = XorShift::new(0x5EED_0006);
    for _ in 0..1000 {
        let s = rand_string(&mut rng, 40);
        let r = no_panic(|| profile::validate_name(&s));
        assert!(
            r.is_ok(),
            "validate_name panicked on {s:?}: {}",
            r.unwrap_err()
        );
    }
    // explicit path-traversal and injection attempts
    for s in ["../x", "a/b", ".", "..", "a\rb", "a\nb", "a b", "-x"] {
        let _ = no_panic(|| profile::validate_name(s));
    }
}

#[test]
fn fuzz_fpm_line_and_shell_quote_never_panic() {
    let mut rng = XorShift::new(0x5EED_0007);
    for _ in 0..1000 {
        let k = rand_string(&mut rng, 8);
        let v = rand_string(&mut rng, 24);
        let r = no_panic(|| {
            let _ = crate::commands::fpm_line(&k, &v);
            crate::commands::shell_quote(&v);
        });
        assert!(
            r.is_ok(),
            "fpm_line/shell_quote panicked on {k:?}={v:?}: {}",
            r.unwrap_err()
        );
    }
}
