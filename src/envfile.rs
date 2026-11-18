//! .env file parsing, canonical serialization, and merge logic.
//!
//! The encrypted payload is a JSON serialization of `BTreeMap<String, String>`
//! (stable key order, correctly handles values containing newlines, quotes,
//! and Unicode). Export serializes it back into standard .env text.
//!
//! Values are **literal**: `$NAME` / `${NAME}` are never substituted, in any
//! quoting style. dotenvy (which expands them against the process environment)
//! is deliberately not used: a secrets file must round-trip byte-exactly, and
//! expansion silently rewrites `$`-laden values — a bcrypt hash
//! (`$2b$12$…`) or a token with `$` would be truncated when the referenced
//! name is unset. Shell-style escapes (`\n`, `\"`, `\\`, `\$`, `\ `) and
//! single/double quoting are still understood.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EnvVars(BTreeMap<String, String>);

impl EnvVars {
    /// Construct from a raw map (production: `import --from-env`; tests)
    pub fn from_map(map: BTreeMap<String, String>) -> Self {
        Self(map)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Look up one variable's value (O(log n) on the sorted map).
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }

    /// Insert or replace one variable; returns true when the key already existed.
    pub fn insert(&mut self, key: String, value: String) -> bool {
        self.0.insert(key, value).is_some()
    }

    /// Remove one variable; returns true when the key existed.
    pub fn remove(&mut self, key: &str) -> bool {
        self.0.remove(key).is_some()
    }

    /// Parse a .env file: comments, `export` prefix, single/double quotes,
    /// escapes, multi-line quoted values, UTF-8 BOM and CRLF. Values are
    /// literal — no `$` substitution (see the module docs).
    pub fn parse_file(path: &Path) -> Result<Self> {
        Self::parse_file_mode(path, false).map(|(vars, _)| vars)
    }

    /// `parse_file` with opt-in expansion (`import --expand`): `$NAME` and
    /// `${NAME}` in bare and double-quoted values are resolved against earlier
    /// keys of the same file, then the process environment. Single-quoted
    /// values, escaped `\$` and `$` not followed by a name stay literal.
    /// Returns the keys whose values were expanded so the caller can name them
    /// (values are never reported).
    pub fn parse_file_expanded(path: &Path) -> Result<(Self, Vec<String>)> {
        Self::parse_file_mode(path, true)
    }

    fn parse_file_mode(path: &Path, expand: bool) -> Result<(Self, Vec<String>)> {
        let raw = std::fs::read(path)
            .with_context(|| format!("cannot read .env file: {}", path.display()))?;
        let text = std::str::from_utf8(&raw).map_err(|_| {
            anyhow::anyhow!("cannot read .env file: {}: not valid UTF-8", path.display())
        })?;
        parse_text(text, expand)
            .with_context(|| format!("failed to parse .env file ({})", path.display()))
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

/// Parse .env text into variables. Errors never echo values: a parse failure
/// in a secrets file must not print the secret it choked on.
///
/// With `expand`, `$NAME` / `${NAME}` in bare and double-quoted values are
/// resolved (earlier keys in the same file first, then the process
/// environment); single-quoted values stay literal. Returns the keys whose
/// values were expanded, in file order.
fn parse_text(text: &str, expand: bool) -> Result<(EnvVars, Vec<String>)> {
    // A Windows-edited file carries a BOM; it must not leak into a key.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut map = BTreeMap::new();
    let mut expanded_keys = Vec::new();
    for (line_no, line) in logical_lines(text)? {
        let mut expanded = false;
        if let Some((key, value)) = parse_line(line_no, &line, &map, expand, &mut expanded)? {
            if expanded {
                expanded_keys.push(key.clone());
            }
            map.insert(key, value);
        }
    }
    Ok((EnvVars(map), expanded_keys))
}

/// Quote state while scanning for physical line boundaries.
#[derive(Clone, Copy, PartialEq)]
enum Scan {
    Bare,
    BareEscape,
    Single,
    Double,
    DoubleEscape,
}

/// Finish a logical line, dropping the `\r` of a CRLF terminator. A raw CR
/// inside an open quote is data and never reaches this function.
fn push_line(out: &mut Vec<(usize, String)>, cur: &mut String, start_line: usize) {
    if cur.ends_with('\r') {
        cur.pop();
    }
    out.push((start_line, std::mem::take(cur)));
}

/// Split into logical lines: a value may span physical lines while a single
/// or double quote is open (certificates, private keys). A comment starts at
/// `#` only where it follows whitespace, and ends that physical line. Returns
/// (1-based start line, text) so later errors can name a line without echoing
/// it.
fn logical_lines(text: &str) -> Result<Vec<(usize, String)>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut line_no = 1usize;
    let mut start_line = 1usize;
    let mut state = Scan::Bare;
    let mut prev_ws = false;
    let mut comment = false;

    for ch in text.chars() {
        if comment {
            if ch == '\n' {
                push_line(&mut out, &mut cur, start_line);
                line_no += 1;
                start_line = line_no;
                prev_ws = false;
                comment = false;
            }
            continue;
        }
        match state {
            Scan::Bare => match ch {
                '\\' => {
                    cur.push(ch);
                    state = Scan::BareEscape;
                }
                '\'' => {
                    cur.push(ch);
                    state = Scan::Single;
                }
                '"' => {
                    cur.push(ch);
                    state = Scan::Double;
                }
                '#' if prev_ws => comment = true,
                '\n' => {
                    push_line(&mut out, &mut cur, start_line);
                    line_no += 1;
                    start_line = line_no;
                    prev_ws = false;
                }
                c => {
                    cur.push(c);
                    prev_ws = c.is_whitespace();
                }
            },
            Scan::BareEscape => {
                cur.push(ch);
                state = Scan::Bare;
            }
            Scan::Single => {
                cur.push(ch);
                if ch == '\'' {
                    state = Scan::Bare;
                }
            }
            Scan::Double => match ch {
                '\\' => {
                    cur.push(ch);
                    state = Scan::DoubleEscape;
                }
                '"' => {
                    cur.push(ch);
                    state = Scan::Bare;
                }
                c => cur.push(c),
            },
            Scan::DoubleEscape => {
                cur.push(ch);
                state = Scan::Double;
            }
        }
    }
    if state != Scan::Bare {
        bail!("line {start_line}: unterminated quote or escape");
    }
    if !cur.is_empty() {
        out.push((start_line, cur));
    }
    Ok(out)
}

/// Parse one logical line. `None` for blank and comment-only lines.
fn parse_line(
    line_no: usize,
    line: &str,
    seen: &BTreeMap<String, String>,
    expand: bool,
    expanded: &mut bool,
) -> Result<Option<(String, String)>> {
    let mut rest = line.trim_start();
    if rest.is_empty() || rest.starts_with('#') {
        return Ok(None);
    }

    let (mut key, after_key) = split_key(line_no, rest)?;
    rest = after_key.trim_start();
    if key == "export" {
        rest = match rest.strip_prefix('=') {
            // `export` used as a variable name itself
            Some(after_eq) => after_eq,
            None => {
                let (inner, after_inner) = split_key(line_no, rest)?;
                key = inner;
                after_inner.trim_start()
            }
        };
    }
    let rest = rest
        .strip_prefix('=')
        .ok_or_else(|| anyhow::anyhow!("line {line_no}: missing '=' after the variable name"))?;

    Ok(Some((
        key,
        parse_value(line_no, rest.trim_start(), seen, expand, expanded)?,
    )))
}

/// Read the variable name at the start of `s` (dotenv makes `.` part of the
/// name; `validate_key` rejects it later with a clearer message).
fn split_key(line_no: usize, s: &str) -> Result<(String, &str)> {
    match s.chars().next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => bail!("line {line_no}: variable name must start with a letter or '_'"),
    }
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .unwrap_or(s.len());
    Ok((s[..end].to_string(), &s[end..]))
}

#[derive(Clone, Copy, PartialEq)]
enum ValueState {
    Bare,
    Escape,
    Single,
    Double,
    DoubleEscape,
    End,
}

/// Parse a value: single quotes are fully literal, double quotes and bare
/// values decode `\n \" \\ \$ \' \ ` only, and a bare value ends at unquoted
/// whitespace. `$` is literal unless `expand` is set; even then it is never
/// special inside single quotes or after a backslash.
fn parse_value(
    line_no: usize,
    s: &str,
    seen: &BTreeMap<String, String>,
    expand: bool,
    expanded: &mut bool,
) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let mut state = ValueState::Bare;
    let mut it = s.chars().peekable();
    while let Some(ch) = it.next() {
        match state {
            ValueState::Bare => match ch {
                '\'' => state = ValueState::Single,
                '"' => state = ValueState::Double,
                '\\' => state = ValueState::Escape,
                '$' if expand => {
                    if expand_reference(line_no, &mut it, seen, &mut out)? {
                        *expanded = true;
                    }
                }
                c if c.is_whitespace() => state = ValueState::End,
                c => out.push(c),
            },
            ValueState::Escape => {
                push_escape(line_no, ch, &mut out)?;
                state = ValueState::Bare;
            }
            ValueState::Single => {
                if ch == '\'' {
                    state = ValueState::Bare;
                } else {
                    out.push(ch);
                }
            }
            ValueState::Double => match ch {
                '"' => state = ValueState::Bare,
                '\\' => state = ValueState::DoubleEscape,
                '$' if expand => {
                    if expand_reference(line_no, &mut it, seen, &mut out)? {
                        *expanded = true;
                    }
                }
                c => out.push(c),
            },
            ValueState::DoubleEscape => {
                push_escape(line_no, ch, &mut out)?;
                state = ValueState::Double;
            }
            ValueState::End => {
                if !ch.is_whitespace() {
                    bail!(
                        "line {line_no}: unexpected text after the value \
                         (quote values that contain spaces)"
                    );
                }
            }
        }
    }
    match state {
        ValueState::Bare | ValueState::End => Ok(out),
        // logical_lines rejects these first; the guard keeps direct callers safe
        _ => bail!("line {line_no}: unterminated quote or escape"),
    }
}

/// Resolve one reference, positioned right after a `$`. Returns `false` (and
/// writes a literal `$`, plus any name-shaped characters it consumed) when the
/// next character cannot start a name — so `$2b$12$…` survives `--expand`
/// unescaped. An unset name is an error: substituting `""` is exactly the
/// silent truncation this mode must not reintroduce. Resolution is one pass;
/// an expanded value is not re-scanned.
fn expand_reference(
    line_no: usize,
    it: &mut std::iter::Peekable<std::str::Chars<'_>>,
    seen: &BTreeMap<String, String>,
    out: &mut String,
) -> Result<bool> {
    let name = if it.peek() == Some(&'{') {
        it.next();
        let mut name = String::new();
        loop {
            match it.next() {
                Some('}') => break,
                Some(c) => name.push(c),
                None => bail!("line {line_no}: unterminated ${{...}} reference"),
            }
        }
        if !is_identifier(&name) {
            bail!(
                "line {line_no}: ${{...}} must contain a variable name \
                 ([A-Za-z_][A-Za-z0-9_]*); defaults and nested forms are not supported"
            );
        }
        name
    } else {
        let mut name = String::new();
        while let Some(&c) = it.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                name.push(c);
                it.next();
            } else {
                break;
            }
        }
        if !is_identifier(&name) {
            out.push('$');
            out.push_str(&name);
            return Ok(false);
        }
        name
    };

    // Earlier keys of the same file win over the ambient environment.
    match seen
        .get(&name)
        .cloned()
        .or_else(|| std::env::var(&name).ok())
    {
        Some(value) => {
            out.push_str(&value);
            Ok(true)
        }
        None => bail!(
            "line {line_no}: {name} is not set; --expand resolves earlier keys in the file \
             and the environment"
        ),
    }
}

/// POSIX identifier, the same shape `validate_key` enforces.
fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn push_escape(line_no: usize, ch: char, out: &mut String) -> Result<()> {
    match ch {
        '\\' | '\'' | '"' | '$' | ' ' => out.push(ch),
        'n' => out.push('\n'),
        _ => bail!(
            "line {line_no}: invalid escape sequence (supported: \\\\ \\' \\\" \\$ \\<space> \\n)"
        ),
    }
    Ok(())
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
    // (excludes space, #, $, quotes, and other chars the parser treats specially)
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
    // Single quotes are fully literal, including backslashes and `$`
    if !v.contains('\'') {
        return format!("'{v}'");
    }
    let mut s = String::with_capacity(v.len() + 2);
    s.push('"');
    for c in v.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            // The parser REJECTS the \r and \t escape sequences but keeps raw
            // CR/TAB/DEL inside double quotes verbatim — emit them raw.
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
    fn get_looks_up_values() {
        let vars = EnvVars::from_map(BTreeMap::from([
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "two".to_string()),
        ]));
        assert_eq!(vars.get("A"), Some("1"));
        assert_eq!(vars.get("B"), Some("two"));
        assert_eq!(vars.get("C"), None);
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

    /// `$` is never substituted — bare, double-quoted, braced or repeated.
    /// Regression: import used to expand these against the process
    /// environment, silently truncating hashes and tokens.
    #[test]
    fn dollar_is_literal() {
        let path = write_temp_env(concat!(
            "BARE=pa$$w0rd$HOME\n",
            "BRACES=${HOME}/bin\n",
            "DQUOTED=\"a $HOME b\"\n",
            "SQUOTED='a $HOME b'\n",
            "HASH=$2b$12$abcdefghijklmnop\n",
        ));
        let vars = EnvVars::parse_file(&path).unwrap();
        let get = |k: &str| vars.get(k).unwrap().to_string();
        assert_eq!(get("BARE"), "pa$$w0rd$HOME");
        assert_eq!(get("BRACES"), "${HOME}/bin");
        assert_eq!(get("DQUOTED"), "a $HOME b");
        assert_eq!(get("SQUOTED"), "a $HOME b");
        assert_eq!(get("HASH"), "$2b$12$abcdefghijklmnop");
    }

    /// Expansion is opt-in, one pass, and scoped to bare/double-quoted
    /// values: earlier file keys win over the environment, single quotes and
    /// escaped `$` stay literal, and `$` before non-name characters does too.
    #[test]
    fn expand_is_opt_in_and_file_scoped() {
        let path = write_temp_env(concat!(
            "BASE=1\n",
            "HOME=filehome\n",
            "DERIVED=$BASE:x\n",
            "BRACED=\"${BASE}:y\"\n",
            "DOUBLE=\"$HOME/bin\"\n",
            "FILEWINS=$HOME\n",
            "SQUOTED='$BASE'\n",
            "ESCAPED=\"\\$BASE\"\n",
            "DIGITS=$2b$12$\n",
            "ENDDOLLAR=tail$\n",
        ));
        // literal mode: nothing moves, not even the file's own HOME
        let plain = EnvVars::parse_file(&path).unwrap();
        assert_eq!(plain.get("DERIVED"), Some("$BASE:x"));
        assert_eq!(plain.get("FILEWINS"), Some("$HOME"));

        let (vars, expanded) = EnvVars::parse_file_expanded(&path).unwrap();
        assert_eq!(vars.get("DERIVED"), Some("1:x"));
        assert_eq!(vars.get("BRACED"), Some("1:y"));
        assert_eq!(vars.get("DOUBLE"), Some("filehome/bin"));
        assert_eq!(vars.get("FILEWINS"), Some("filehome"));
        assert_eq!(vars.get("SQUOTED"), Some("$BASE"));
        assert_eq!(vars.get("ESCAPED"), Some("$BASE"));
        assert_eq!(vars.get("DIGITS"), Some("$2b$12$"));
        assert_eq!(vars.get("ENDDOLLAR"), Some("tail$"));
        assert_eq!(expanded, vec!["DERIVED", "BRACED", "DOUBLE", "FILEWINS"]);
    }

    /// With no earlier key of that name, expansion falls back to the process
    /// environment.
    #[test]
    fn expand_falls_back_to_the_environment() {
        let Ok(home) = std::env::var("HOME") else {
            return; // environment without HOME: nothing to assert
        };
        let path = write_temp_env("ENVREF=$HOME\nBRACED=\"${HOME}\"\n");
        let (vars, expanded) = EnvVars::parse_file_expanded(&path).unwrap();
        assert_eq!(vars.get("ENVREF"), Some(home.as_str()));
        assert_eq!(vars.get("BRACED"), Some(home.as_str()));
        assert_eq!(expanded, vec!["ENVREF", "BRACED"]);
    }

    /// An unset name is a hard error (never `""`), unsupported `${...}` forms
    /// are rejected, and neither message echoes the surrounding value.
    #[test]
    fn expand_rejects_unset_and_malformed_references() {
        let unset = write_temp_env("K=$ENVPOUCH_UNSET_TEST_9f3a\n");
        let err = format!("{:#}", EnvVars::parse_file_expanded(&unset).unwrap_err());
        assert!(err.contains("ENVPOUCH_UNSET_TEST_9f3a is not set"), "{err}");

        let unterminated = write_temp_env("K=${HOME\n");
        let err = format!(
            "{:#}",
            EnvVars::parse_file_expanded(&unterminated).unwrap_err()
        );
        assert!(err.contains("unterminated ${...}"), "{err}");

        let defaulted = write_temp_env("K=${HOME:-/tmp}\n");
        let err = format!(
            "{:#}",
            EnvVars::parse_file_expanded(&defaulted).unwrap_err()
        );
        assert!(err.contains("defaults and nested forms"), "{err}");

        let embedded = write_temp_env("K=\"secret-$NOPE_9f3a\"\n");
        let err = format!("{:#}", EnvVars::parse_file_expanded(&embedded).unwrap_err());
        assert!(
            !err.contains("secret-"),
            "error must not leak the value: {err}"
        );
    }

    /// Double quotes and bare values decode `\n`, `\$`, `\"`, `\\`; `\r` and
    /// `\t` are hard parse errors; raw CR/TAB/DEL are preserved verbatim.
    /// `format_value` relies on exactly this behavior.
    #[test]
    fn double_quote_escapes() {
        let parse_value = |input: &str| -> Result<Option<String>, String> {
            let path = write_temp_env(&format!("K=\"{input}\"\n"));
            match EnvVars::parse_file(&path) {
                Ok(v) => Ok(v.get("K").map(str::to_string)),
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

    /// Single quotes are fully literal: backslashes (including one right
    /// before the closing quote), `$`, and raw control characters survive.
    #[test]
    fn single_quote_is_literal() {
        let parse_value = |input: &str| -> Result<Option<String>, String> {
            let path = write_temp_env(&format!("K='{input}'\n"));
            match EnvVars::parse_file(&path) {
                Ok(v) => Ok(v.get("K").map(str::to_string)),
                Err(e) => Err(e.to_string()),
            }
        };
        assert_eq!(parse_value("a\\").unwrap(), Some("a\\".into()));
        assert_eq!(parse_value("a\\\\").unwrap(), Some("a\\\\".into()));
        assert_eq!(parse_value("a\\b").unwrap(), Some("a\\b".into()));
        assert_eq!(parse_value("a\\$b").unwrap(), Some("a\\$b".into()));
        for (input, want) in [("a\rb", "a\rb"), ("a\tb", "a\tb"), ("a\nb", "a\nb")] {
            assert_eq!(
                parse_value(input).unwrap(),
                Some(want.into()),
                "single-quote raw {input:?}"
            );
        }
    }

    /// A quoted value may span physical lines (certificates, private keys);
    /// the newline is part of the value and the next line is a new entry.
    #[test]
    fn quoted_value_spans_lines() {
        let path = write_temp_env("KEY=\"line1\nline2\"\nAFTER=ok\n");
        let vars = EnvVars::parse_file(&path).unwrap();
        assert_eq!(vars.get("KEY"), Some("line1\nline2"));
        assert_eq!(vars.get("AFTER"), Some("ok"));
        assert_eq!(vars.len(), 2);
    }

    /// `#` starts a comment only after whitespace; trailing text after a
    /// closed value is a hard error. Parse errors name the line but never
    /// echo the value (secrets hygiene).
    #[test]
    fn comments_trailing_text_and_error_hygiene() {
        let path = write_temp_env("A=1 # comment\nB=v#not-comment\nC=\"x # y\" # c\n");
        let vars = EnvVars::parse_file(&path).unwrap();
        assert_eq!(vars.get("A"), Some("1"));
        assert_eq!(vars.get("B"), Some("v#not-comment"));
        assert_eq!(vars.get("C"), Some("x # y"));
        assert_eq!(vars.len(), 3);

        let bad = write_temp_env("D=\"a\" b\n");
        assert!(EnvVars::parse_file(&bad).is_err());

        let leaky = write_temp_env("K=\"hunter2\\q\"\n");
        let err = format!("{:#}", EnvVars::parse_file(&leaky).unwrap_err());
        assert!(
            !err.contains("hunter2"),
            "error must not leak the value: {err}"
        );
        assert!(err.contains("line 1"), "error should name the line: {err}");
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
    /// (critical: quoting, escapes, `$`-laden values).
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
