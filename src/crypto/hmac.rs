//! Full implementation of HMAC-SHA1 in accordance with [RFC 2104](http://tools.ietf.org/html/rfc2104)
//!
//!# Examples
//!
//!```
//!use rust_oauth::crypto::hmac;
//!let key = "key".as_bytes();
//!let msg = "The quick brown fox jumps over the lazy dog".as_bytes();
//!let hmac = hmac::hmac_sha1(msg, key);
//!```

use std::ops::BitXor;
use super::sha1;

// HMAC constants defined in RFC 2104

const BLOCKSIZE : usize = 64;
const IPAD : U8BLOCK = U8BLOCK([0x36u8; BLOCKSIZE]);
const OPAD : U8BLOCK = U8BLOCK([0x5cu8; BLOCKSIZE]);

#[derive(Copy)]
struct U8BLOCK([u8; BLOCKSIZE]);

impl BitXor for U8BLOCK {
    type Output = U8BLOCK;

    fn bitxor(self, _rhs: U8BLOCK) -> U8BLOCK {
        let U8BLOCK(mut x) = self;
        let U8BLOCK(r) = _rhs;
        for i in range(0, BLOCKSIZE) {
            x[i] = x[i] ^ r[i];
        };
        U8BLOCK(x)
    }
}

/// Generate the hmac using the hashing function, message, and key provided.
#[stable]
pub fn hmac_sha1(msg : &[u8], key : &[u8]) -> [u8; 20] {
    let mut key_new : [u8; BLOCKSIZE] = [0u8; BLOCKSIZE];

    if key.len() > BLOCKSIZE {
        let hash = sha1::sha1(key);
        for x in range(0, hash.len()) {
            key_new[x] = hash[x];
        }
    } else {
        for x in range(0, key.len()) {
            key_new[x] = key[x];
        }
    }
    let mut v = Vec::new();
    let U8BLOCK(temp) = U8BLOCK(key_new) ^ IPAD;
    v.push_all(&temp);
    v.push_all(msg);
    let temp2 : [u8; 20] = sha1::sha1(&v);
    v = Vec::new();
    let U8BLOCK(temp) = U8BLOCK(key_new) ^ OPAD;
    v.push_all(&temp);
    v.push_all(&temp2);
    sha1::sha1(&v)

}

#[cfg(test)]
mod tests {
    use super::hmac_sha1;

    #[test]
    fn hmac_test1() {
        let key = "key".as_bytes();
        let msg = "The quick brown fox jumps over the lazy dog".as_bytes();
        let h = hmac_sha1(msg, key);
        assert_eq!(h,
            [0xdeu8, 0x7cu8, 0x9bu8, 0x85u8, 0xb8u8,
             0xb7u8, 0x8au8, 0xa6u8, 0xbcu8, 0x8au8,
             0x7au8, 0x36u8, 0xf7u8, 0x0au8, 0x90u8,
             0x70u8, 0x1cu8, 0x9du8, 0xb4u8, 0xd9u8]);
    }

    #[test]
    fn hmac_test2() {
        let key = "".as_bytes();
        let msg = "".as_bytes();
        let h = hmac_sha1(msg, key);
        assert_eq!(h,
            [0xfbu8, 0xdbu8, 0x1du8, 0x1bu8, 0x18u8,
             0xaau8, 0x6cu8, 0x08u8, 0x32u8, 0x4bu8,
             0x7du8, 0x64u8, 0xb7u8, 0x1fu8, 0xb7u8,
             0x63u8, 0x70u8, 0x69u8, 0x0eu8, 0x1du8])
    }

}
