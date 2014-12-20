
pub mod crypto;
pub mod oauth;
#[cfg(test)]
mod tests {
    use crypto::sha1::{sha1};
    use oauth::oauth1;

    // Session initialization and setup test
    #[test]
    fn hw() {
        let s = oauth1::Session::new("Hello", "World");
    }
/*
    /// Classic test
    #[test]
    fn sha1_test1(){
        let test = "abcd".to_string().into_bytes();
        let test : &[u8] = test.as_slice();
        assert!(sha1(test) ==
            [0x81u8, 0xfeu8, 0x8bu8, 0xfeu8, 0x87u8,
             0x57u8, 0x6cu8, 0x3eu8, 0xcbu8, 0x22u8,
             0x42u8, 0x6fu8, 0x8eu8, 0x57u8, 0x84u8,
             0x73u8, 0x82u8, 0x91u8, 0x7au8, 0xcfu8])
    }

    /// Classic test
    #[test]
    fn sha1_test2(){
        let test = "The quick brown fox jumped over the lazy dog".to_string().into_bytes();
        let test : &[u8] = test.as_slice();
        assert!(sha1(test) ==
            [0xf6u8, 0x51u8, 0x36u8, 0x40u8, 0xf3u8,
             0x04u8, 0x5eu8, 0x97u8, 0x68u8, 0xb2u8,
             0x39u8, 0x78u8, 0x56u8, 0x25u8, 0xcau8,
             0xa6u8, 0xa2u8, 0x58u8, 0x88u8, 0x42u8])
    }

    /// Test of multi block input
    #[test]
    fn sha1_test3(){
        let test = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string().into_bytes();
        let test : &[u8] = test.as_slice();
        assert!(sha1(test) ==
            [0x49u8, 0x56u8, 0xe9u8, 0x28u8, 0x66u8,
             0xb2u8, 0x7fu8, 0xa9u8, 0x0bu8, 0x8fu8,
             0x81u8, 0x80u8, 0xd1u8, 0xfbu8, 0x3au8,
             0x75u8, 0xcfu8, 0x96u8, 0xfeu8, 0x1du8])
    }

    /// Test of 512 bit input
    #[test]
    fn sha1_test4(){
        let test = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string().into_bytes();
        let test : &[u8] = test.as_slice();
        assert!(sha1(test) ==
            [0xdau8, 0xc2u8, 0x3cu8, 0x13u8, 0x66u8,
             0xddu8, 0x53u8, 0xb6u8, 0x2du8, 0x93u8,
             0xfcu8, 0xc4u8, 0xb6u8, 0x36u8, 0x33u8,
             0xe6u8, 0xd5u8, 0x2fu8, 0x1cu8, 0x4cu8])
    }

    /// Test 504 bit input
    #[test]
    fn sha1_test5(){
        let test = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string().into_bytes();
        let test : &[u8] = test.as_slice();
        assert!(sha1(test) ==
            [0x23u8, 0xcau8, 0x04u8, 0x35u8, 0xedu8,
             0xc0u8, 0x88u8, 0x1au8, 0xeeu8, 0xc6u8,
             0xa8u8, 0xcbu8, 0x72u8, 0x91u8, 0xccu8,
             0x06u8, 0x28u8, 0x27u8, 0x1bu8, 0x75u8])
    }

    /// Test of 520 bit input
    #[test]
    fn sha1_test6(){
        let test = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string().into_bytes();
        let test : &[u8] = test.as_slice();
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
        let test = "X".to_string().into_bytes();
        let test : &[u8] = test.as_slice();
        assert!(sha1(test) ==
            [0xf1u8, 0xc5u8, 0xa3u8, 0xe3u8, 0x15u8,
             0x93u8, 0xb6u8, 0x80u8, 0xd2u8, 0x2du8,
             0x5cu8, 0x0au8, 0x82u8, 0x4bu8, 0x96u8,
             0x4bu8, 0x60u8, 0x8du8, 0x8fu8, 0x80u8])
    }
*/
}
