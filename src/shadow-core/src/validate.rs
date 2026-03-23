// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Username and groupname validation rules.
//!
//! Based on POSIX Portable Filename Character Set plus Linux extensions.
//! See: POSIX 3.437 (User Name), man 8 useradd.

use crate::error::ShadowError;

/// Maximum username length on Linux.
const MAX_USERNAME_LEN: usize = 32;

/// Validate a username according to Linux conventions.
///
/// Rules (from man 8 useradd, POSIX):
/// - Must not be empty
/// - Must not exceed 32 characters
/// - First character must be a lowercase letter or underscore
/// - Remaining characters: lowercase letters, digits, underscores, hyphens, periods
/// - Must not end with a period (historically problematic)
/// - Must not consist of only dots
///
/// # Errors
///
/// Returns `ShadowError::Validation` if the username violates any rule.
pub fn validate_username(name: &str) -> Result<(), ShadowError> {
    if name.is_empty() {
        return Err(ShadowError::Validation("username must not be empty".into()));
    }

    if name.len() > MAX_USERNAME_LEN {
        return Err(ShadowError::Validation(
            format!("username '{name}' exceeds maximum length of {MAX_USERNAME_LEN} characters")
                .into(),
        ));
    }

    let mut chars = name.chars();
    // Name is guaranteed non-empty by the check above.
    let Some(first) = chars.next() else {
        unreachable!("empty name already rejected");
    };

    if !first.is_ascii_lowercase() && first != '_' {
        return Err(ShadowError::Validation(
            format!("username '{name}' must start with a lowercase letter or underscore").into(),
        ));
    }

    for ch in chars {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '_' && ch != '-' && ch != '.' {
            return Err(ShadowError::Validation(
                format!("username '{name}' contains invalid character '{ch}'").into(),
            ));
        }
    }

    if name.ends_with('.') {
        return Err(ShadowError::Validation(
            format!("username '{name}' must not end with a period").into(),
        ));
    }

    if name.chars().all(|c| c == '.') {
        return Err(ShadowError::Validation(
            format!("username '{name}' must not consist only of periods").into(),
        ));
    }

    Ok(())
}

/// A validated Linux username.
///
/// Guarantees that the contained string passes all `validate_username` rules.
/// Use `Username::new()` to validate and construct.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Username(String);

impl Username {
    /// Validate and create a new `Username`.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Validation` if the name violates any rule.
    pub fn new(name: &str) -> Result<Self, ShadowError> {
        validate_username(name)?;
        Ok(Self(name.to_string()))
    }

    /// Get the username as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for Username {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_usernames() {
        assert!(validate_username("root").is_ok());
        assert!(validate_username("_apt").is_ok());
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("test-user").is_ok());
        assert!(validate_username("test.user").is_ok());
        assert!(validate_username("a").is_ok());
    }

    #[test]
    fn test_empty_username() {
        assert!(validate_username("").is_err());
    }

    #[test]
    fn test_too_long() {
        let long_name = "a".repeat(33);
        assert!(validate_username(&long_name).is_err());
        let max_name = "a".repeat(32);
        assert!(validate_username(&max_name).is_ok());
    }

    #[test]
    fn test_invalid_first_char() {
        assert!(validate_username("1user").is_err());
        assert!(validate_username("-user").is_err());
        assert!(validate_username(".user").is_err());
        assert!(validate_username("User").is_err());
    }

    #[test]
    fn test_invalid_chars() {
        assert!(validate_username("user@name").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("user:name").is_err());
    }

    #[test]
    fn test_trailing_period() {
        assert!(validate_username("user.").is_err());
    }

    // -------------------------------------------------------------------
    // Issue #16: additional edge case tests
    // -------------------------------------------------------------------

    #[test]
    fn test_unicode_username_rejected() {
        assert!(validate_username("café").is_err());
    }

    #[test]
    fn test_null_byte_rejected() {
        assert!(validate_username("\0user").is_err());
    }

    #[test]
    fn test_max_length_32_ok() {
        let name = "a".repeat(32);
        assert!(validate_username(&name).is_ok());
    }

    #[test]
    fn test_length_33_rejected() {
        let name = "a".repeat(33);
        assert!(validate_username(&name).is_err());
    }

    #[test]
    fn test_only_dots_rejected() {
        assert!(validate_username("..").is_err());
        assert!(validate_username("...").is_err());
    }

    #[test]
    fn test_hyphen_start_rejected() {
        assert!(validate_username("-user").is_err());
    }

    #[test]
    fn test_uppercase_rejected() {
        assert!(validate_username("Root").is_err());
    }

    // -------------------------------------------------------------------
    // Username newtype tests
    // -------------------------------------------------------------------

    #[test]
    fn test_username_newtype_valid() {
        let u = Username::new("testuser").unwrap();
        assert_eq!(u.as_str(), "testuser");
        assert_eq!(&*u, "testuser"); // Deref
        assert_eq!(format!("{u}"), "testuser"); // Display
    }

    #[test]
    fn test_username_newtype_invalid() {
        assert!(Username::new("").is_err());
        assert!(Username::new("Root").is_err());
    }
}
