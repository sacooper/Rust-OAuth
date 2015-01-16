//! Crypto functions for OAuth 1.0
//!
 
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
