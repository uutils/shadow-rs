// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore lstchg

//! Parser and writer for `/etc/shadow`.
//!
//! File format (man 5 shadow):
//! ```text
//! username:password:lstchg:min:max:warn:inactive:expire:reserved
//! ```
//!
//! All date fields are in days since epoch (1970-01-01).

use std::fmt;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::str::FromStr;

use crate::error::ShadowError;

/// A single entry from `/etc/shadow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowEntry {
    /// Login name (must match an `/etc/passwd` entry).
    pub name: String,
    /// Encrypted password hash (or `!`/`*` for locked/no-login).
    pub passwd: String,
    /// Date of last password change (days since epoch), or empty.
    pub last_change: Option<i64>,
    /// Minimum days between password changes, or empty.
    pub min_age: Option<i64>,
    /// Maximum days a password is valid, or empty.
    pub max_age: Option<i64>,
    /// Days before expiry to warn user, or empty.
    pub warn_days: Option<i64>,
    /// Days after expiry until account is disabled, or empty.
    pub inactive_days: Option<i64>,
    /// Account expiration date (days since epoch), or empty.
    pub expire_date: Option<i64>,
    /// Reserved field (unused).
    pub reserved: String,
}

/// Parse an optional numeric field — empty string becomes `None`.
fn parse_optional_field(field: &str) -> Result<Option<i64>, ShadowError> {
    if field.is_empty() {
        Ok(None)
    } else {
        field
            .parse::<i64>()
            .map(Some)
            .map_err(|e| ShadowError::Parse(format!("invalid numeric field '{field}': {e}")))
    }
}

/// Format an optional numeric field — `None` becomes empty string.
fn fmt_optional(val: Option<i64>) -> String {
    match val {
        Some(v) => v.to_string(),
        None => String::new(),
    }
}

impl fmt::Display for ShadowEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.name,
            self.passwd,
            fmt_optional(self.last_change),
            fmt_optional(self.min_age),
            fmt_optional(self.max_age),
            fmt_optional(self.warn_days),
            fmt_optional(self.inactive_days),
            fmt_optional(self.expire_date),
            self.reserved,
        )
    }
}

impl FromStr for ShadowEntry {
    type Err = ShadowError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 9 {
            return Err(ShadowError::Parse(format!(
                "expected 9 colon-separated fields, got {}",
                fields.len()
            )));
        }

        Ok(Self {
            name: fields[0].to_string(),
            passwd: fields[1].to_string(),
            last_change: parse_optional_field(fields[2])?,
            min_age: parse_optional_field(fields[3])?,
            max_age: parse_optional_field(fields[4])?,
            warn_days: parse_optional_field(fields[5])?,
            inactive_days: parse_optional_field(fields[6])?,
            expire_date: parse_optional_field(fields[7])?,
            reserved: fields[8].to_string(),
        })
    }
}

/// Read all entries from an `/etc/shadow`-formatted file.
///
/// # Errors
///
/// Returns `ShadowError` if the file cannot be opened or contains malformed entries.
pub fn read_shadow_file(path: &Path) -> Result<Vec<ShadowEntry>, ShadowError> {
    let file = std::fs::File::open(path).map_err(|e| ShadowError::IoPath(e, path.to_owned()))?;
    let reader = io::BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        entries.push(trimmed.parse()?);
    }

    Ok(entries)
}

/// Write entries to an `/etc/shadow`-formatted file.
///
/// # Errors
///
/// Returns `ShadowError` on I/O write failure.
pub fn write_shadow<W: Write>(entries: &[ShadowEntry], mut writer: W) -> Result<(), ShadowError> {
    for entry in entries {
        writeln!(writer, "{entry}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_entry() {
        let entry: ShadowEntry = "root:$6$hash:19000:0:99999:7:::".parse().unwrap();
        assert_eq!(entry.name, "root");
        assert_eq!(entry.passwd, "$6$hash");
        assert_eq!(entry.last_change, Some(19000));
        assert_eq!(entry.min_age, Some(0));
        assert_eq!(entry.max_age, Some(99999));
        assert_eq!(entry.warn_days, Some(7));
        assert_eq!(entry.inactive_days, None);
        assert_eq!(entry.expire_date, None);
        assert_eq!(entry.reserved, "");
    }

    #[test]
    fn test_parse_locked_account() {
        let entry: ShadowEntry = "locked:!:19000::::::".parse().unwrap();
        assert_eq!(entry.passwd, "!");
        assert_eq!(entry.min_age, None);
    }

    #[test]
    fn test_roundtrip() {
        let line = "testuser:$6$rounds=5000$salt$hash:19500:0:99999:7:30::";
        let entry: ShadowEntry = line.parse().unwrap();
        assert_eq!(entry.to_string(), line);
    }

    #[test]
    fn test_all_empty_optional_fields() {
        let entry: ShadowEntry = "svc:*:::::::".parse().unwrap();
        assert_eq!(entry.last_change, None);
        assert_eq!(entry.min_age, None);
        assert_eq!(entry.max_age, None);
        assert_eq!(entry.warn_days, None);
        assert_eq!(entry.inactive_days, None);
        assert_eq!(entry.expire_date, None);
    }
}
