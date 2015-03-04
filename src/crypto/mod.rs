//! Crypto functions for OAuth 1.0
//!

use std::fmt;

#[unstable]
pub mod sha1;

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
        (*self) << bits  | (*self) >> (32 - bits)
    }
}

#[derive(Copy, Debug, PartialEq, Eq, Clone)]
#[unstable]
/// Signature Type
pub enum SignatureMethod {
    /// HMACSHA1
    HMACSHA1,
    /// RSASHA1
    RSASHA1,
    /// Plaintext
    PLAINTEXT
}

impl fmt::Display for SignatureMethod {
    fn fmt(&self, f : &mut fmt::Formatter) -> fmt::Result{
        let out = match *self {
            SignatureMethod::HMACSHA1 => {"HMACSHA1"},
            SignatureMethod::RSASHA1  => {"RSA-SHA1"},
            SignatureMethod::PLAINTEXT => {"PLAINTEXT"}
        };
        write!(f, "{}", out)
    }
}

pub fn sign() {

}
