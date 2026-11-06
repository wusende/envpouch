//! .env file parsing, canonical serialization, and merge logic.
//!
//! The encrypted payload is a JSON serialization of `BTreeMap<String, String>`
//! (stable key order, correctly handles values containing newlines, quotes,
//! and Unicode). Export serializes it back into standard .env text.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EnvVars(BTreeMap<String, String>);

impl EnvVars {
    /// Test/construction helper
    #[allow(dead_code)]
    pub fn from_map(map: BTreeMap<String, String>) -> Self {
        Self(map)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }

    /// Parse a .env file with dotenvy (supports comments, `export` prefix,
    /// quotes, multi-line values).
    /// Note: `$VAR` references in values are expanded by dotenvy (consistent
    /// with the dotenv ecosystem). Single-quoted values are NOT expanded.
    pub fn parse_file(path: &Path) -> Result<Self> {
        let iter = dotenvy::from_path_iter(path)
            .with_context(|| format!("cannot read .env file: {}", path.display()))?;
        let mut map = BTreeMap::new();
        for item in iter {
            let (k, v) = item.map_err(|e| {
                anyhow::anyhow!("failed to parse .env file ({}): {e}", path.display())
            })?;
            map.insert(k, v);
        }
        Ok(Self(map))
    }

    /// Merge `other` into `self`: same-name keys take the value from `other`,
    /// keys unique to `self` are preserved. Returns (added, updated) counts.
    pub fn merge(&mut self, other: EnvVars) -> (usize, usize) {
        let mut added = 0;
        let mut updated = 0;
        for (k, v) in other.0 {
            if self.0.insert(k, v).is_none() {
                added += 1;
            } else {
                updated += 1;
            }
        }
        (added, updated)
    }

    /// Serialize to JSON (Zeroizing so the buffer is wiped when dropped).
    pub fn to_json(&self) -> Result<Zeroizing<Vec<u8>>> {
        let bytes =
            serde_json::to_vec(&self.0).context("failed to serialize environment variables")?;
        Ok(Zeroizing::new(bytes))
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .context("decrypted payload is not a valid variable record (file may be corrupted)")
    }

    /// Produce .env text. Values are quoted as needed so that re-importing
    /// yields identical key/value semantics.
    pub fn to_env_text(&self) -> String {
        let mut out = String::from("# exported by envpouch\n");
        for (k, v) in &self.0 {
            out.push_str(k);
            out.push('=');
            out.push_str(&format_value(v));
            out.push('\n');
        }
        out
    }
}

/// Reject keys that are unsafe to pass to child processes (spec §4.4 plus a
/// strict superset for production safety): the name must be a POSIX portable
/// identifier `[A-Za-z_][A-Za-z0-9_]*`. This subsumes the spec's explicit
/// rejections (empty, '=' and NUL, digit-leading) and additionally catches
/// garbage from Windows-edited files such as UTF-8 BOM prefixes, spaces, and
/// dashes — keys like those would silently break `run`'s injection.
/// NUL in values is rejected because `std::process::Command` panics on it.
pub fn validate_key(key: &str, value: &str) -> Result<()> {
    // NB: `all()` on an empty iterator is vacuously true — the explicit
    // is_empty() check is what actually rejects empty key names.
    let valid = !key.is_empty()
        && key.chars().enumerate().all(|(i, c)| match i {
            0 => c.is_ascii_alphabetic() || c == '_',
            _ => c.is_ascii_alphanumeric() || c == '_',
        });
    if !valid {
        anyhow::bail!(
            "invalid variable name '{key}' (must match [A-Za-z_][A-Za-z0-9_]*); \
             check for BOM, spaces or dashes in the source file"
        );
    }
    if value.contains('\0') {
        anyhow::bail!("value of variable '{key}' contains NUL");
    }
    Ok(())
}

/// Single-quoted values are literal (no expansion, no escapes) — preferred.
/// Values containing a single quote fall back to double quotes with escapes.
fn format_value(v: &str) -> String {
    if v.is_empty() {
        return String::new();
    }
    // No quotes needed for values made purely of safe characters
    // (excludes space, #, $, quotes, and other chars dotenvy treats specially)
    let is_safe = v.bytes().all(|b| {
        matches!(
            b,
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'/'
                | b':' | b'+' | b'@' | b'%' | b'=' | b',' | b'~'
        )
    });
    if is_safe {
        return v.to_string();
    }
    // Single-quote path (values are literal inside it) — but NOT when the
    // value ends with a backslash: dotenvy treats a `\'` sequence as an
    // escaped quote, so `'a\'` (trailing backslash before the closer) is a
    // hard parse error (fuzz discovery). Double quotes handle it via `\\`.
    if !v.contains('\'') && !v.ends_with('\\') {
        return format!("'{v}'");
    }
    let mut s = String::with_capacity(v.len() + 2);
    s.push('"');
    for c in v.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '$' => s.push_str("\\$"),
            '\n' => s.push_str("\\n"),
            // dotenvy REJECTS the \r and \t escape sequences (hard parse
            // error, probed empirically) but preserves raw CR/TAB/DEL and
            // newlines inside double quotes verbatim — emit them raw.
            _ => s.push(c),
        }
    }
    s.push('"');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn write_temp_env(content: &str) -> std::path::PathBuf {
        // Leak the TempDir so the temp file outlives the helper (fine for tests)
        let dir: &'static tempfile::TempDir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let path = dir.path().join("test.env");
        std::fs::write(&path, content).expect("failed to write temp file");
        path
    }

    #[test]
    fn parse_basic() {
        let path = write_temp_env(
            "# comment\nFOO=bar\nexport BAZ=\"quoted value\"\n\nEMPTY=\nQUOTED='single  # not comment'\n",
        );
        let vars = EnvVars::parse_file(&path).unwrap();
        let get = |k: &str| {
            vars.iter()
                .find(|(a, _)| a.as_str() == k)
                .unwrap()
                .1
                .clone()
        };
        assert_eq!(get("FOO"), "bar");
        assert_eq!(get("BAZ"), "quoted value");
        assert_eq!(get("EMPTY"), "");
        assert_eq!(get("QUOTED"), "single  # not comment");
        assert_eq!(vars.len(), 4);
    }

    #[test]
    fn parse_error_reported() {
        let path = write_temp_env("INVALID KEY LINE WITHOUT EQUALS\n");
        assert!(EnvVars::parse_file(&path).is_err());
    }

    #[test]
    fn merge_semantics() {
        let mut base = EnvVars::from_map(BTreeMap::from([
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "2".to_string()),
        ]));
        let incoming = EnvVars::from_map(BTreeMap::from([
            ("B".to_string(), "3".to_string()),
            ("C".to_string(), "4".to_string()),
        ]));
        let (added, updated) = base.merge(incoming);
        assert_eq!((added, updated), (1, 1));
        let get = |k: &str| {
            base.iter()
                .find(|(a, _)| a.as_str() == k)
                .unwrap()
                .1
                .clone()
        };
        assert_eq!(get("A"), "1");
        assert_eq!(get("B"), "3");
        assert_eq!(get("C"), "4");
    }

    #[test]
    fn json_roundtrip() {
        let vars = EnvVars::from_map(BTreeMap::from([
            ("KEY".to_string(), "value\nwith newline".to_string()),
            ("UNI".to_string(), "unicode值".to_string()),
        ]));
        let json = vars.to_json().unwrap();
        let back = EnvVars::from_json(&json).unwrap();
        assert!(vars.iter().eq(back.iter()));
    }

    #[test]
    fn key_validation() {
        assert!(validate_key("FOO", "bar").is_ok());
        assert!(validate_key("_HIDDEN", "x").is_ok());
        assert!(validate_key("A1", "x").is_ok());
        // spec §4.4 explicit rejections
        assert!(validate_key("", "bar").is_err());
        assert!(validate_key("A=B", "x").is_err());
        assert!(validate_key("A\0B", "x").is_err());
        assert!(validate_key("1ABC", "x").is_err());
        assert!(validate_key("FOO", "va\0l").is_err());
        // strict superset: garbage from Windows-edited files must not be stored
        assert!(validate_key("MY-KEY", "x").is_err());
        assert!(validate_key("FOO BAR", "x").is_err());
        assert!(validate_key("\u{feff}FOO", "x").is_err());
        assert!(validate_key("FOO\r", "x").is_err());
    }

    /// Windows-edited files use CRLF line endings; values must not keep `\r`.
    /// Documents dotenvy's double-quote escape semantics (probed empirically,
    /// dotenvy 0.15): `\n`, `\$`, `\"`, `\\` are decoded; `\r` and `\t` are
    /// REJECTED with a hard parse error; raw CR/TAB/DEL inside the quotes are
    /// preserved verbatim. `format_value` relies on exactly this behavior.
    #[test]
    fn probe_dotenvy_double_quote_escapes() {
        let parse_value = |input: &str| -> Result<Option<String>, String> {
            let path = write_temp_env(&format!("K=\"{input}\"\n"));
            match EnvVars::parse_file(&path) {
                Ok(v) => Ok(v
                    .iter()
                    .find(|(k, _)| k.as_str() == "K")
                    .map(|(_, v)| v.clone())),
                Err(e) => Err(e.to_string()),
            }
        };
        // supported escapes
        assert_eq!(parse_value("a\\nb").unwrap(), Some("a\nb".into()));
        assert_eq!(parse_value("a\\$b").unwrap(), Some("a$b".into()));
        assert_eq!(parse_value("a\\\"b").unwrap(), Some("a\"b".into()));
        assert_eq!(parse_value("a\\\\b").unwrap(), Some("a\\b".into()));
        // rejected escapes — hard parse errors
        assert!(parse_value("a\\rb").is_err());
        assert!(parse_value("a\\tb").is_err());
        // raw control characters preserved verbatim
        assert_eq!(parse_value("a\rb").unwrap(), Some("a\rb".into()));
        assert_eq!(parse_value("a\tb").unwrap(), Some("a\tb".into()));
        assert_eq!(parse_value("a\u{7f}b").unwrap(), Some("a\u{7f}b".into()));
    }

    /// Raw CR/TAB/newline inside single quotes are preserved literally.
    #[test]
    fn probe_dotenvy_single_quote_raw() {
        for (input, want) in [("a\rb", "a\rb"), ("a\tb", "a\tb"), ("a\nb", "a\nb")] {
            let path = write_temp_env(&format!("K='{input}'\n"));
            let vars = EnvVars::parse_file(&path).unwrap();
            let got = vars
                .iter()
                .find(|(k, _)| k.as_str() == "K")
                .map(|(_, v)| v.clone());
            assert_eq!(got.as_deref(), Some(want), "single-quote raw {input:?}");
        }
    }

    /// Documents dotenvy's single-quote semantics (probed empirically,
    /// dotenvy 0.15): contents are literal EXCEPT `\'` which escapes the
    /// closing quote (so a trailing backslash before the closer is a hard
    /// parse error); `\\`, `\$`, `\b` stay literal backslashes.
    #[test]
    fn probe_dotenvy_single_quote_backslash() {
        let parse_value = |input: &str| -> Result<Option<String>, String> {
            let path = write_temp_env(&format!("K='{input}'\n"));
            match EnvVars::parse_file(&path) {
                Ok(v) => Ok(v
                    .iter()
                    .find(|(k, _)| k.as_str() == "K")
                    .map(|(_, v)| v.clone())),
                Err(e) => Err(e.to_string()),
            }
        };
        assert!(
            parse_value("a\\").is_err(),
            "trailing backslash before closer errors"
        );
        assert!(parse_value("a\\'b").is_err(), "\\' escapes the closer");
        // literal backslashes elsewhere
        assert_eq!(parse_value("a\\\\").unwrap(), Some("a\\\\".into()));
        assert_eq!(parse_value("a\\b").unwrap(), Some("a\\b".into()));
        assert_eq!(parse_value("a\\$b").unwrap(), Some("a\\$b".into()));
    }

    #[test]
    fn parse_crlf_file() {
        let path = write_temp_env("FOO=bar\r\nBAZ=qux\r\n");
        let vars = EnvVars::parse_file(&path).unwrap();
        let get = |k: &str| {
            vars.iter()
                .find(|(a, _)| a.as_str() == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("FOO").as_deref(), Some("bar"));
        assert_eq!(get("BAZ").as_deref(), Some("qux"));
        assert_eq!(vars.len(), 2);
    }

    /// Exported text must re-import to exactly the same key/value pairs
    /// (critical: dotenvy's handling of single quotes, double quotes, escapes).
    #[test]
    fn env_text_roundtrip_tricky_values() {
        let cases: Vec<(String, String)> = vec![
            ("PLAIN".into(), "hello".into()),
            ("WITH_SPACE".into(), "hello world".into()),
            ("DOLLAR".into(), "pa$$w0rd$HOME".into()),
            ("SQUOTE".into(), "it's".into()),
            ("DQUOTE".into(), "say \"hi\"".into()),
            ("SQUOTE_AND_DOLLAR".into(), "it's $HOME".into()),
            ("NEWLINE".into(), "line1\nline2".into()),
            ("EMPTY".into(), "".into()),
            ("EQ".into(), "a=b".into()),
            ("HASH".into(), "# not comment".into()),
            ("TAB".into(), "a\tb".into()),
            ("PADDED".into(), "  padded  ".into()),
            ("UNI".into(), "unicode ünï".into()),
            ("BACKSLASH".into(), "C:\\path\\to".into()),
        ];
        let vars = EnvVars::from_map(cases.iter().cloned().collect());
        let text = vars.to_env_text();

        let path = write_temp_env(&text);
        let reparsed = EnvVars::parse_file(&path).unwrap();

        let original: BTreeMap<&str, &str> = cases
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let roundtripped: BTreeMap<&str, &str> = reparsed
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(original, roundtripped);
    }
}
