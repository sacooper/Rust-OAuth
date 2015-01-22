//! OAuth 1
//!
//!# Example
//!
//! TODO
use std::default::Default;
use std::fmt;
use super::{SignatureMethod, AuthorizationHeader, generate_nonce, generate_timestamp};

impl Default for SignatureMethod {
    fn default() -> SignatureMethod {
        SignatureMethod::HMAC_SHA1}
}

impl fmt::String for SignatureMethod {
    fn fmt(&self, f : &mut fmt::Formatter) -> fmt::Result{
        let out = match *self {
            SignatureMethod::HMAC_SHA1 => {"HMAC-SHA1"},
            SignatureMethod::RSA_SHA1  => {"RSA-SHA1"},
            SignatureMethod::PLAINTEXT => {"PLAINTEXT"}
        };
        write!(f, "{}", out)
    }
}

#[unstable]
pub struct Session<'a> {
    oauth_consumer_key : &'a str,
    oauth_token : &'a str,
    oauth_token_secret : &'a str,
    oauth_signature_method : SignatureMethod,
    oauth_signature : String,
    oauth_timestamp : String,
    oauth_nonce : String,
}

// Creates a Session Object, which contains all reused
// parameters for OAuth 1.0A
impl<'a> Session<'a> {
    pub fn new (consumer_key: &'a str, token: &'a str, secret: &'a str,
                signature_method: SignatureMethod) -> Session<'a> {
        Session {
            oauth_consumer_key: consumer_key,
            oauth_token: token,
            oauth_token_secret : secret,
            oauth_signature_method: signature_method,
            oauth_signature: Default::default(),
            oauth_timestamp: Default::default(),
            oauth_nonce: Default::default(),
        }
    }
    // Returns a base string URI, ecnoded with [RFC3986]
    // This gets used to generate the `oauth_signature`
    // This might be used to send a request as well
    fn get_base_string(mut self, base_url: &'a str) -> String {
        if (self.oauth_signature_method == SignatureMethod::PLAINTEXT) {
            format!("{}&oauth_consumer_key=\"{}\"&\
                    oauth_signature=\"{}\"&oauth_signature_method=\"{}\"&\
                    oauth_token=\"{}\"&oauth_version=\"1.0\"",
                    base_url, self.oauth_consumer_key, self.oauth_signature,
                    self.oauth_signature_method, self.oauth_token)
        } else {
            self.oauth_nonce = generate_nonce();
            self.oauth_timestamp = generate_timestamp();
            format!("{}&oauth_consumer_key=\"{}\"&oauth_nonce=\"{}\"&\
                    oauth_signature=\"{}\"&oauth_signature_method=\"{}\"&\
                    oauth_timestamp=\"{}\"&oauth_token=\"{}\"&oauth_version=\"1.0\"",
                    base_url, self.oauth_consumer_key, self.oauth_nonce,
                    self.oauth_signature, self.oauth_signature_method,
                    self.oauth_timestamp, self.oauth_token)
        }
    }
    fn request(&self, base_url: String) {

    }
}


// Creates a URL encoded String containing headers
// This should be called everytime you make a request, since the
// `oauth_timestamp` and `oauth_nonce` need to freshly made

impl<'a> AuthorizationHeader for Session<'a>{
    fn get_header(&self) -> String {
            let header = format!("Authorization: OAuth oauth_consumer_key=\"{}\" \
                            oauth_signature=\"{}\", oauth_signature_method=\"{}\", \
                            oauth_token=\"{}\", oauth_version=\"1.0\"",
                            self.oauth_consumer_key, self.oauth_signature,
                            self.oauth_signature_method, self.oauth_token);

            match self.oauth_signature_method {
                SignatureMethod::PLAINTEXT => header,
                _ => format!("{}, oauth_timestamp=\"{}\", oauth_nonce=\"{}\"",
                            header, generate_timestamp(), generate_nonce())
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate url;
    use super::Session;
    use super::super::{SignatureMethod, AuthorizationHeader};
    //use self::url::percent_encoding::{utf8_percent_encode, FORM_URLENCODED};

    // Session initialization and setup test
    #[test]
    fn hw() {
    let s = Session::new("k0azC44q2c0DgF7ua9YZ6Q",
                        "119544186-6YZKqkECA9Z0bxq9bA1vzzG7tfPotCml4oTySkzj",
                        "zvNmU9daj9V00118H9KQBozQQsZt4pyLQcZdc",
                        SignatureMethod::HMAC_SHA1);
    let base_string = s.get_base_string("https://api.twitter.com/1.1/statuses/user_timeline.json");
    //println!("\n\n{}\n\n{}\n\n", base_string, utf8_percent_encode(base_string.as_slice(), FORM_URLENCODED));
    }
}
