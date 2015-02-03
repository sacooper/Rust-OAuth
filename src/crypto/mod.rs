//! Crypto functions for OAuth 1.0
//!

use std::fmt;

#[unstable]
pub mod sha1;

#[experimental]
pub mod rsa;

#[unstable]
pub mod hmac;

#[stable]
trait CircularShift {
    fn circular_shift(&self, bits : usize) -> Self;
}

#[stable]
impl CircularShift for u32 {
    fn circular_shift(&self, bits : usize) -> u32 {
        *self << bits  | *self >> (32us - bits)
    }
}

#[derive(Copy, Debug, PartialEq, Eq, Clone)]
#[unstable]
/// Signature Type
pub enum SignatureMethod {
    /// HMAC_SHA1
    HMAC_SHA1,
    /// RSA_SHA1
    RSA_SHA1,
    /// Plaintext
    PLAINTEXT
}

impl fmt::Display for SignatureMethod {
    fn fmt(&self, f : &mut fmt::Formatter) -> fmt::Result{
        let out = match *self {
            SignatureMethod::HMAC_SHA1 => {"HMAC-SHA1"},
            SignatureMethod::RSA_SHA1  => {"RSA-SHA1"},
            SignatureMethod::PLAINTEXT => {"PLAINTEXT"}
        };
        write!(f, "{}", out)
    }
}

pub fn sign() {

}
