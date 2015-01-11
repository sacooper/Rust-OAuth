//! Crypto functions for OAuth 1.0
//!

use std::default::Default;

#[unstable]
pub mod sha1;

#[unstable]
pub mod rsa;

#[unstable]
pub mod hmac;

trait CircularShift {
    fn circular_shift(&mut self, bits : usize) -> Self;
}

impl CircularShift for u32 {
    fn circular_shift(&mut self, bits : usize) -> u32 {
        *self << bits  | *self >> (32us - bits)
    }
}
