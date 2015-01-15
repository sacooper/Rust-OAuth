//! OAuth 1
//!
//!# Example
//!
//! TODO
extern crate time;

use std::default::Default;
use std::fmt::{Show, Result, Formatter};
use self::time::now_utc;
use std::rand::{thread_rng, Rng};

pub struct Session<'a> {
    oauth_consumer_key : &'a str,
    oauth_token : &'a str,
    oauth_token_secret : &'a str,
    oauth_signature_method : &'a str,
    oauth_signature : &'a str,
}

// TODO: add to crypto library?
fn get_nonce() -> String {
    thread_rng().gen_ascii_chars()
                .take(10)
                .collect()
}

impl<'a> Session<'a> {
    pub fn new (consumer_key: &'a str, token: &'a str, secret: &'a str,
                signature_method: &'a str) -> Session<'a> {
        Session {
            oauth_consumer_key: consumer_key,
            oauth_token: token,
            oauth_token_secret : secret,
            oauth_signature_method: signature_method,
            oauth_signature: "TODO",
        }
    }
    pub fn get_temporary_credentials(&self) {

    }
    fn get_header(&self) -> String {
        let header = format!("Authorization: OAuth oauth_consumer_key=\"{}\" \
                oauth_signature=\"{}\", oauth_signature_method=\"{}\", \
                oauth_token=\"{}\", oauth_version=\"1.0\"",
                self.oauth_consumer_key, self.oauth_signature,
                self.oauth_signature_method, self.oauth_token);

        match self.oauth_signature_method {
            "PLAINTEXT" => header,
            _ => format!("{}, oauth_timestamp=\"{}\", oauth_nonce=\"{}\"",
                        header, now_utc().to_timespec().sec, get_nonce())
        }
    }
}

#[cfg(test)]
mod tests {
    use oauth::oauth1::Session;

    // Session initialization and setup test
    #[test]
    fn hw() {
        let s = Session::new("k0azC44q2c0DgF7ua9YZ6Q",
                            "119544186-6YZKqkECA9Z0bxq9bA1vzzG7tfPotCml4oTySkzj",
                            "zvNmU9daj9V00118H9KQBozQQsZt4pyLQcZdc",
                            "HMAC-SHA1");
        println!("{}", s.get_header());
    }
}
