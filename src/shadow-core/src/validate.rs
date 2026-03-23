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
        return Err(ShadowError::Validation(format!(
            "username '{name}' exceeds maximum length of {MAX_USERNAME_LEN} characters"
        )));
    }

    let mut chars = name.chars();
    // Name is guaranteed non-empty by the check above.
    let Some(first) = chars.next() else {
        unreachable!("empty name already rejected");
    };

    if !first.is_ascii_lowercase() && first != '_' {
        return Err(ShadowError::Validation(format!(
            "username '{name}' must start with a lowercase letter or underscore"
        )));
    }

    for ch in chars {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '_' && ch != '-' && ch != '.' {
            return Err(ShadowError::Validation(format!(
                "username '{name}' contains invalid character '{ch}'"
            )));
        }
    }

    if name.ends_with('.') {
        return Err(ShadowError::Validation(format!(
            "username '{name}' must not end with a period"
        )));
    }

    if name.chars().all(|c| c == '.') {
        return Err(ShadowError::Validation(format!(
            "username '{name}' must not consist only of periods"
        )));
    }

    Ok(())
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
}
