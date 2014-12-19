use std::iter::{range_inclusive};

const K0 : u32 = 0x5A827999u32;
const K1 : u32 = 0x6ED9EBA1u32;
const K2 : u32 = 0x8F1BBCDCu32;
const K3 : u32 = 0xCA62C1D6u32;
const H_INIT : [u32, ..5] =
    [0x67452301u32, 0xEFCDAB89u32, 0x98BADCFEu32, 0x10325476u32, 0xC3D2E1F0u32];


trait CircularShift {

    fn circular_shift(&mut self, bits : uint) -> Self;
}

impl CircularShift for u32 {
    fn circular_shift(&mut self, bits : uint) -> u32 {
        *self << bits  | *self >> (32u - bits)
    }
}

pub fn sha1(msg : &[u8]) -> [u8,..20] {
    let mut h : [u32, ..5] = H_INIT;
    let len : u64 = msg.len() as u64;

    let mut block : [u8, ..64];
    let mut i = 0u;

    while len - ((i*64u) as u64) > 449u64 {
        block = [0u8, ..64];
        for j in range(0u,64u){block[j] = msg[64*i+j ];}
        digest_block(&block, &mut h);
        i += 1;
    }

    let mut j = 0u;
    block = [0u8, ..64];
    while len > (i*64 + j) as u64 {
        block[j] = msg[64*i+j];
        j+=1;
    }

    let len = len * 8;
    block[j] = 0x80u8;
    block[56] = ((len & 0xFF00000000000000u64) >> 56u) as u8;
    block[57] = ((len & 0x00FF000000000000u64) >> 48u) as u8;
    block[58] = ((len & 0x0000FF0000000000u64) >> 40u) as u8;
    block[59] = ((len & 0x000000FF00000000u64) >> 32u) as u8;
    block[60] = ((len & 0x00000000FF000000u64) >> 24u) as u8;
    block[61] = ((len & 0x0000000000FF0000u64) >> 16u) as u8;
    block[62] = ((len & 0x000000000000FF00u64) >> 8u) as u8;
    block[63] =  (len & 0x00000000000000FFu64) as u8;

    for x in block.iter(){
        print!("{0:X} ", *x);}
    println!("");

    for x in h.iter(){
        print!("{0:X} ", *x);}
    println!("");

    digest_block(&block, &mut h);

    for x in h.iter(){
        print!("{0:X} ", *x);}
    println!("");

    let mut res : [u8, ..20] = [0u8, ..20];
    for i in range(0u,5) {
        res[4u*i] =   ((h[i] & 0xFF000000) >> 24u) as u8;
        res[4u*i+1] = ((h[i] & 0x00FF0000) >> 16u) as u8;
        res[4u*i+2] = ((h[i] & 0x0000FF00) >> 8u) as u8;
        res[4u*i+3] =  (h[i] & 0x000000FF) as u8;
    }
    res
}

fn digest_block(block : &[u8, ..64], h : &mut[u32, ..5]){
    let mut t : uint;
    let mut w : [u32, ..80u] = [0u32, ..80u];

    for i in range_inclusive(0u,15){
        w[i] = ((block[4u*i] as u32) << 24u) | ((block[4u*i + 1u] as u32) << 16u)
                | ((block[4u*i+2u] as u32) << 8u) | block[4u*i+3u] as u32;
    }

    for x in w.iter(){
        print!("{0:X}", *x);
    } println!("");

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

// fn main(){
//     // let test = "The quick brown fox jumped over the lazy dog".to_string().into_bytes();
//     let test = "abcd".to_string().into_bytes();
//     let x : &[u8] = test.as_slice();
//
//     let z = sha1(x);
//
//     for x in z.iter(){
//         print!("{0:X} ", *x);
//     }
//     println!("");
// }