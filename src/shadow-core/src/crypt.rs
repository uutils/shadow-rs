// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Safe wrapper around POSIX `crypt(3)` for password hash verification.
//!
//! This is one of only two modules (along with `pam`) where `unsafe_code`
//! is permitted, because `crypt(3)` is a C library function.

use std::ffi::CString;

use subtle::ConstantTimeEq;

use crate::error::ShadowError;

#[link(name = "crypt")]
unsafe extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

/// Verify a plaintext password against a crypt(3) hash.
///
/// Returns `true` if the password matches the hash, `false` otherwise.
///
/// # Errors
///
/// Returns `ShadowError` if the inputs contain null bytes.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, ShadowError> {
    let c_password = CString::new(password)
        .map_err(|_| ShadowError::Auth("password contains null byte".into()))?;
    let c_hash =
        CString::new(hash).map_err(|_| ShadowError::Auth("hash contains null byte".into()))?;

    // SAFETY: crypt() is provided by libcrypt/glibc. Both arguments are valid
    // null-terminated C strings. The returned pointer is to a static/thread-local
    // buffer managed by crypt().
    let result = unsafe { crypt(c_password.as_ptr(), c_hash.as_ptr()) };

    if result.is_null() {
        return Ok(false);
    }

    // SAFETY: crypt() returned a non-null pointer to a null-terminated string.
    let result_str = unsafe { std::ffi::CStr::from_ptr(result) };
    let result_str = result_str.to_str().unwrap_or("");

    // Constant-time comparison prevents timing side-channel attacks
    // that could leak password hash information.
    Ok(result_str.as_bytes().ct_eq(hash.as_bytes()).into())
}
