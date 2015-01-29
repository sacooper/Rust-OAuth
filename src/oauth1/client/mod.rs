extern crate time;

use self::time::now_utc;
use std::rand::{OsRng, Rng};
use std::iter::Iterator;

pub mod session;
pub mod builder;

#[derive(Copy, Show, PartialEq, Eq, Clone)]
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

pub enum HTTPMethod {
    GET,
    POST,
    DELETE,
    PUT,
    HEAD
}

pub trait AuthorizationHeader {
    fn get_header(&self) -> String;
}

// TODO: add to crypto library?
// TODO: Should we have a longer nonce than 10?
fn generate_nonce() -> String {

    OsRng::new().unwrap()
                .gen_ascii_chars()
                .take(10)
                .collect()
}

fn generate_timestamp() -> String{
    now_utc().to_timespec().sec.to_string()
}
