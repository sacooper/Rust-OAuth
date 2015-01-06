//! Crypto functions for OAuth 1.0
//!

use std::default::Default;

#[unstable]
pub mod sha1;

#[unstable]
pub mod rsa;

#[unstable]
pub mod hmac;

#[derive(Copy, Show, PartialEq, Eq, Clone)]
#[unstable]
/// Signature Type
pub enum SignatureType {
    /// HMAC_SHA1
    HMAC_SHA1,
    /// RSA_SHA1
    RSA_SHA1,
    /// Plaintext
    PLAINTEXT
}

impl Default for SignatureType {
    fn default() -> SignatureType {SignatureType::HMAC_SHA1}
}

trait CircularShift {
    fn circular_shift(&mut self, bits : uint) -> Self;
}

impl CircularShift for u32 {
    fn circular_shift(&mut self, bits : uint) -> u32 {
        *self << bits  | *self >> (32u - bits)
    }
}
