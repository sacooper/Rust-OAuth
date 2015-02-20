//! Full implementation of SHA1 hash algorithm in accordance with
//! [RFC 3174](https://tools.ietf.org/html/rfc3174)
//!
//!# Examples
//!
//!```rust
//! use rust_oauth::crypto::sha1::sha1;
//! let msg = "The quick brown fox jumped over the lazy dog".as_bytes();
//! let hash = sha1(msg);
//!```
//!

use std::iter::{range_inclusive};
use std::cmp::{min};
use super::CircularShift;

const K0 : u32 = 0x5A827999u32;
const K1 : u32 = 0x6ED9EBA1u32;
const K2 : u32 = 0x8F1BBCDCu32;
const K3 : u32 = 0xCA62C1D6u32;
const H_INIT : [u32; 5] =
    [0x67452301u32, 0xEFCDAB89u32, 0x98BADCFEu32, 0x10325476u32, 0xC3D2E1F0u32];

/// Create a hash of the input data `msg`.
#[stable]
pub fn sha1(msg : &[u8]) -> [u8; 20] {
    let mut h : [u32; 5] = H_INIT;
    let len : u64 = msg.len() as u64;

    let mut block : [u8; 64];
    let mut i = 0;

    while len > (63 + ((i*64) as u64)) {
        block = [0u8; 64];
        for j in range(0, min(64u64, len) as usize){block[j] = msg[64*i+j ];}
        digest_block(&block, &mut h);
        i += 1;
    }

    block = [0u8; 64];
    let mut j = 0;

    while len > (i*64 + j) as u64 && j < 64 {
        block[j] = msg[64*i+j];
        j+=1;
    }

    block[(len as usize % 64)] = 0x80u8;

    if j==63 {
        digest_block(&block, &mut h);
        block=[0; 64];
    }

    let len = len * 8;
    block[56] = ((len & 0xFF00000000000000u64) >> 56) as u8;
    block[57] = ((len & 0x00FF000000000000u64) >> 48) as u8;
    block[58] = ((len & 0x0000FF0000000000u64) >> 40) as u8;
    block[59] = ((len & 0x000000FF00000000u64) >> 32) as u8;
    block[60] = ((len & 0x00000000FF000000u64) >> 24) as u8;
    block[61] = ((len & 0x0000000000FF0000u64) >> 16) as u8;
    block[62] = ((len & 0x000000000000FF00u64) >> 8) as u8;
    block[63] =  (len & 0x00000000000000FFu64) as u8;

    digest_block(&block, &mut h);

    let mut res : [u8; 20] = [0u8; 20];
    for i in range(0,5) {
        res[4*i] =   ((h[i] & 0xFF000000) >> 24) as u8;
        res[4*i+1] = ((h[i] & 0x00FF0000) >> 16) as u8;
        res[4*i+2] = ((h[i] & 0x0000FF00) >> 8) as u8;
        res[4*i+3] =  (h[i] & 0x000000FF) as u8;
    }
    res
}

#[stable]
fn digest_block(block : &[u8; 64], h : &mut[u32; 5]){
    let mut t : usize;
    let mut w : [u32; 80] = [0u32; 80];

    for i in range_inclusive(0,15){
        w[i] = ((block[4*i] as u32) << 24) | ((block[4*i + 1] as u32) << 16)
                | ((block[4*i+2] as u32) << 8) | block[4*i+3] as u32;
    }

    t = 16;
    while t < 80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).circular_shift(1);
        t += 1;
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut temp : u32;

    t = 0;
    while t < 20 {
        temp = a.circular_shift(5) + ((b & c) | (!b & d)) + e + w[t] + K0;
        e = d;
        d = c;
        c = b.circular_shift(30);
        b = a;
        a = temp;
        t+=1;
    }

    while t < 40 {
        temp = a.circular_shift(5) + (b ^ c ^ d) + e + w[t] + K1;
        e = d;
        d = c;
        c = b.circular_shift(30);
        b = a;
        a = temp;
        t += 1;
    }

    while t < 60 {
        temp = a.circular_shift(5) + ((b & c) | (b & d) | (c & d)) + e + w[t] + K2;
        e = d;
        d = c;
        c = b.circular_shift(30);
        b = a;
        a = temp;
        t += 1;
    }

    while t < 80 {
        temp = a.circular_shift(5) + (b ^ c ^ d) + e + w[t] + K3;
        e = d;
        d = c;
        c = b.circular_shift(30);
        b = a;
        a = temp;
        t += 1;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

#[cfg(test)]
mod tests {
    use super::{sha1};

    /// Classic test
    #[test]
    fn sha1_test1(){
        let test = "abcd".as_bytes();
        assert!(sha1(test) ==
        [0x81u8, 0xfeu8, 0x8bu8, 0xfeu8, 0x87u8,
        0x57u8, 0x6cu8, 0x3eu8, 0xcbu8, 0x22u8,
        0x42u8, 0x6fu8, 0x8eu8, 0x57u8, 0x84u8,
        0x73u8, 0x82u8, 0x91u8, 0x7au8, 0xcfu8])
    }

    /// Classic test
    #[test]
    fn sha1_test2(){
        let test = "The quick brown fox jumped over the lazy dog".as_bytes();
        assert!(sha1(test) ==
        [0xf6u8, 0x51u8, 0x36u8, 0x40u8, 0xf3u8,
        0x04u8, 0x5eu8, 0x97u8, 0x68u8, 0xb2u8,
        0x39u8, 0x78u8, 0x56u8, 0x25u8, 0xcau8,
        0xa6u8, 0xa2u8, 0x58u8, 0x88u8, 0x42u8])
    }

    /// Test of multi block input
    #[test]
    fn sha1_test3(){
        let test = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ".as_bytes();
        assert!(sha1(test) ==
        [0x49u8, 0x56u8, 0xe9u8, 0x28u8, 0x66u8,
        0xb2u8, 0x7fu8, 0xa9u8, 0x0bu8, 0x8fu8,
        0x81u8, 0x80u8, 0xd1u8, 0xfbu8, 0x3au8,
        0x75u8, 0xcfu8, 0x96u8, 0xfeu8, 0x1du8])
    }

    /// Test of 512 bit input
    #[test]
    fn sha1_test4(){
        let test = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".as_bytes();
        assert!(sha1(test) ==
        [0xdau8, 0xc2u8, 0x3cu8, 0x13u8, 0x66u8,
        0xddu8, 0x53u8, 0xb6u8, 0x2du8, 0x93u8,
        0xfcu8, 0xc4u8, 0xb6u8, 0x36u8, 0x33u8,
        0xe6u8, 0xd5u8, 0x2fu8, 0x1cu8, 0x4cu8])
    }

    /// Test 504 bit input
    #[test]
    fn sha1_test5(){
        let test = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".as_bytes();
        assert!(sha1(test) ==
        [0x23u8, 0xcau8, 0x04u8, 0x35u8, 0xedu8,
        0xc0u8, 0x88u8, 0x1au8, 0xeeu8, 0xc6u8,
        0xa8u8, 0xcbu8, 0x72u8, 0x91u8, 0xccu8,
        0x06u8, 0x28u8, 0x27u8, 0x1bu8, 0x75u8])
    }

    /// Test of 520 bit input
    #[test]
    fn sha1_test6(){
        let test = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".as_bytes();
        assert!(sha1(test) ==
        [0xf1u8, 0xc5u8, 0xa3u8, 0xe3u8, 0x15u8,
        0x93u8, 0xb6u8, 0x80u8, 0xd2u8, 0x2du8,
        0x5cu8, 0x0au8, 0x82u8, 0x4bu8, 0x96u8,
        0x4bu8, 0x60u8, 0x8du8, 0x8fu8, 0x80u8])
    }

    /// Negative test
    #[test]
    #[should_fail]
    fn sha1_fail1(){
        let test = "X".as_bytes();
        assert!(sha1(test) ==
        [0xf1u8, 0xc5u8, 0xa3u8, 0xe3u8, 0x15u8,
        0x93u8, 0xb6u8, 0x80u8, 0xd2u8, 0x2du8,
        0x5cu8, 0x0au8, 0x82u8, 0x4bu8, 0x96u8,
        0x4bu8, 0x60u8, 0x8du8, 0x8fu8, 0x80u8])
    }
}
