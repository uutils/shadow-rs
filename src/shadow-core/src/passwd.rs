// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore gecos

//! Parser and writer for `/etc/passwd`.
//!
//! File format (man 5 passwd):
//! ```text
//! username:password:uid:gid:gecos:home:shell
//! ```
//!
//! Each field is colon-separated. The password field is typically `x`
//! (indicating the hash is in `/etc/shadow`).

use std::fmt;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::str::FromStr;

use crate::error::ShadowError;

/// A single entry from `/etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    /// Login name.
    pub name: String,
    /// Encrypted password (usually `x` — real hash in `/etc/shadow`).
    pub passwd: String,
    /// Numeric user ID.
    pub uid: u32,
    /// Numeric primary group ID.
    pub gid: u32,
    /// GECOS / comment field (real name, room, phone, etc.).
    pub gecos: String,
    /// Home directory.
    pub home: String,
    /// Login shell.
    pub shell: String,
}

impl fmt::Display for PasswdEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}:{}:{}",
            self.name, self.passwd, self.uid, self.gid, self.gecos, self.home, self.shell
        )
    }
}

impl FromStr for PasswdEntry {
    type Err = ShadowError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 7 {
            return Err(ShadowError::Parse(format!(
                "expected 7 colon-separated fields, got {}",
                fields.len()
            )));
        }

        let uid = fields[2]
            .parse::<u32>()
            .map_err(|e| ShadowError::Parse(format!("invalid UID '{}': {e}", fields[2])))?;
        let gid = fields[3]
            .parse::<u32>()
            .map_err(|e| ShadowError::Parse(format!("invalid GID '{}': {e}", fields[3])))?;

        Ok(Self {
            name: fields[0].to_string(),
            passwd: fields[1].to_string(),
            uid,
            gid,
            gecos: fields[4].to_string(),
            home: fields[5].to_string(),
            shell: fields[6].to_string(),
        })
    }
}

/// Read all entries from an `/etc/passwd`-formatted file.
///
/// Skips blank lines and lines starting with `#`.
///
/// # Errors
///
/// Returns `ShadowError` if the file cannot be opened or contains malformed entries.
pub fn read_passwd_file(path: &Path) -> Result<Vec<PasswdEntry>, ShadowError> {
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

/// Write entries to an `/etc/passwd`-formatted file.
///
/// This writes to the provided writer. For atomic file replacement,
/// use this with `atomic::AtomicFile`.
///
/// # Errors
///
/// Returns `ShadowError` on I/O write failure.
pub fn write_passwd<W: Write>(entries: &[PasswdEntry], mut writer: W) -> Result<(), ShadowError> {
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
        let entry: PasswdEntry = "root:x:0:0:root:/root:/bin/bash".parse().unwrap();
        assert_eq!(entry.name, "root");
        assert_eq!(entry.passwd, "x");
        assert_eq!(entry.uid, 0);
        assert_eq!(entry.gid, 0);
        assert_eq!(entry.gecos, "root");
        assert_eq!(entry.home, "/root");
        assert_eq!(entry.shell, "/bin/bash");
    }

    #[test]
    fn test_parse_empty_gecos() {
        let entry: PasswdEntry = "nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin"
            .parse()
            .unwrap();
        assert_eq!(entry.name, "nobody");
        assert_eq!(entry.gecos, "");
    }

    #[test]
    fn test_parse_wrong_field_count() {
        let result = "root:x:0:0".parse::<PasswdEntry>();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_uid() {
        let result = "root:x:abc:0:root:/root:/bin/bash".parse::<PasswdEntry>();
        assert!(result.is_err());
    }

    #[test]
    fn test_roundtrip() {
        let line = "testuser:x:1000:1000:Test User:/home/testuser:/bin/zsh";
        let entry: PasswdEntry = line.parse().unwrap();
        assert_eq!(entry.to_string(), line);
    }

    #[test]
    fn test_write_passwd() {
        let entries = vec![
            "root:x:0:0:root:/root:/bin/bash"
                .parse::<PasswdEntry>()
                .unwrap(),
            "nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin"
                .parse::<PasswdEntry>()
                .unwrap(),
        ];
        let mut buf = Vec::new();
        write_passwd(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(
            output,
            "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n"
        );
    }
}
