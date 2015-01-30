extern crate time;

use self::time::now_utc;
use std::rand::{OsRng, Rng};
use std::iter::Iterator;
use std::fmt;

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

impl fmt::Display for SignatureMethod {
    fn fmt(&self, f : &mut fmt::Formatter) -> fmt::Result{
        let out = match *self {
            SignatureMethod::HMAC_SHA1 => {"HMAC-SHA1"},
            SignatureMethod::RSA_SHA1  => {"RSA-SHA1"},
            SignatureMethod::PLAINTEXT => {"PLAINTEXT"}
        };
        write!(f, "{}", out)
    }
}

#[derive(Copy, Show, PartialEq, Eq, Clone)]
#[unstable]
pub enum HTTPMethod {
    GET,
    POST,
    DELETE,
    PUT,
    HEAD
}

impl fmt::Display for HTTPMethod {
    fn fmt(&self, f : &mut fmt::Formatter) -> fmt::Result{
        let out = match *self {
            HTTPMethod::GET     => {"GET"},
            HTTPMethod::POST    => {"POST"},
            HTTPMethod::DELETE  => {"DELETE"},
            HTTPMethod::PUT     => {"PUT"},
            HTTPMethod::HEAD   => {"HEAD"}
        };
        write!(f, "{}", out)
    }
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
