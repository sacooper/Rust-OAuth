
pub mod sha1;

#[cfg(test)]
mod tests {
    use sha1::{sha1};
    #[test]
    fn t1(){
        let test = "abcd".to_string().into_bytes();
        let test : &[u8] = test.as_slice();
        assert!(sha1(test) ==
            [0x81u8, 0xfeu8, 0x8bu8, 0xfeu8, 0x87u8,
             0x57u8, 0x6cu8, 0x3eu8, 0xcbu8, 0x22u8,
             0x42u8, 0x6fu8, 0x8eu8, 0x57u8, 0x84u8,
             0x73u8, 0x82u8, 0x91u8, 0x7au8, 0xcfu8])
    }

    #[test]
    fn t2(){
        let test = "The quick brown fox jumped over the lazy dog".to_string().into_bytes();
        let test : &[u8] = test.as_slice();
        assert!(sha1(test) ==
            [0xf6u8, 0x51u8, 0x36u8, 0x40u8, 0xf3u8,
             0x04u8, 0x5eu8, 0x97u8, 0x68u8, 0xb2u8,
             0x39u8, 0x78u8, 0x56u8, 0x25u8, 0xcau8,
             0xa6u8, 0xa2u8, 0x58u8, 0x88u8, 0x42u8])
    }

    #[test]
    fn t3(){
        let test = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string().into_bytes();
        let test : &[u8] = test.as_slice();
        assert!(sha1(test) ==
            [0x49u8, 0x56u8, 0xe9u8, 0x28u8, 0x66u8,
             0xb2u8, 0x7fu8, 0xa9u8, 0x0bu8, 0x8fu8,
             0x81u8, 0x80u8, 0xd1u8, 0xfbu8, 0x3au8,
             0x75u8, 0xcfu8, 0x96u8, 0xfeu8, 0x1du8])
    }
}
