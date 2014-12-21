//! Full implementation of HMAC in accordance with [RFC 2104](http://tools.ietf.org/html/rfc2104)
//!
//!# Examples
//!
//!```
//!use rust_oauth::crypto::{sha1, hmac};
//!let key = "key".to_string().into_bytes();
//!let msg = "The quick brown fox jumps over the lazy dog".to_string().into_bytes();
//!let hmac = hmac::hmac(|x|{sha1::sha1(x)},msg.as_slice(), key.as_slice());
//!
//!
//!

use std::ops::{BitXor};

const BLOCKSIZE : uint = 64;
const IPAD : [u8, ..BLOCKSIZE] = [0x36u8, ..BLOCKSIZE];
const OPAD : [u8, ..BLOCKSIZE] = [0x5cu8, ..BLOCKSIZE];

struct U8BLOCK([u8, ..BLOCKSIZE]);

///
pub fn hmac(hash : |&[u8]|->[u8, ..20], msg : &[u8], key_orig : &[u8]) -> [u8, ..20]{
    let mut key : [u8, ..BLOCKSIZE] = [0u8, ..BLOCKSIZE];

    if key_orig.len() > BLOCKSIZE{
        let hash = hash(key_orig);
        for x in range(0, hash.len()){
            key[x] = hash[x];
        }
    } else {
        for x in range(0, key_orig.len()){
            key[x] = key_orig[x];
        }
    }
    let mut v = Vec::new();
    v.push_all(&(U8BLOCK(key) ^ IPAD));
    v.push_all(msg);
    let temp : [u8, ..20] = hash(v.as_slice());
    println!("");
    for x in v.iter(){
        print!("{}", *x as char);
    }; println!("");
    for x in temp.iter(){
        print!("{0:X} ", *x);
    }; println!("");
    v = Vec::new();
    v.push_all(&(U8BLOCK(key) ^ OPAD));
    v.push_all(&temp);
    for x in v.iter(){
        print!("{}", *x as char);
        }; println!("");
    for x in hash(v.as_slice()).iter(){
        print!("{} ", *x);
        }; println!("");
    hash(v.as_slice())

}

impl BitXor<[u8, ..BLOCKSIZE], [u8, ..BLOCKSIZE]> for U8BLOCK{
    fn bitxor(self, _rhs : [u8, ..BLOCKSIZE]) -> [u8, ..BLOCKSIZE]{
        let U8BLOCK(t) = self;
        let mut x = t;
        for i in range(0, BLOCKSIZE){
            x[i] = t[i] ^ _rhs[i];
        };
        x
    }
}

#[cfg(test)]
mod tests {
    use super::hmac;
    use super::super::sha1::sha1;

    #[test]
    fn hamc_test1(){
        let key = "key".to_string().into_bytes();
        let msg = "The quick brown fox jumps over the lazy dog".to_string().into_bytes();
        let h = hmac(|x|{sha1(x)},msg.as_slice(), key.as_slice());
        println!("");
        assert!(h ==
            [0xdeu8, 0x7cu8, 0x9bu8, 0x85u8, 0xb8u8,
             0xb7u8, 0x8au8, 0xa6u8, 0xbcu8, 0x8au8,
             0x7au8, 0x36u8, 0xf7u8, 0x0au8, 0x90u8,
             0x70u8, 0x1cu8, 0x9du8, 0xb4u8, 0xd9u8]);
    }
}
