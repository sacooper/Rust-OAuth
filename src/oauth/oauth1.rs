//! OAuth 1
//!
//!# Example
//!
//! TODO
extern crate time;

use std::default::Default;
use std::fmt;
use self::time::now_utc;
use std::rand::{thread_rng, Rng};

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

pub trait AuthorizationHeader {
    fn get_header(&self) -> String;
}

#[unstable]
pub struct Session<'a> {
    oauth_consumer_key : &'a str,
    oauth_token : &'a str,
    oauth_token_secret : &'a str,
    oauth_signature_method : SignatureMethod,
    oauth_signature : String,
    oauth_timestamp : i64,
    oauth_nonce : String,
}

// TODO: add to crypto library?
// TODO: Should we have a longer nonce than 10?
fn generate_nonce() -> String {
    thread_rng().gen_ascii_chars()
                .take(10)
                .collect()
}

fn generate_timestamp() -> i64{
    now_utc().to_timespec().sec
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
            format!("{}oauth_consumer_key=\"{}\"&oauth_nonce=\"{}\"&\
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
    use super::{Session, SignatureMethod, AuthorizationHeader};

    // Session initialization and setup test
    #[test]
    fn hw() {
    let s = Session::new("k0azC44q2c0DgF7ua9YZ6Q",
                        "119544186-6YZKqkECA9Z0bxq9bA1vzzG7tfPotCml4oTySkzj",
                        "zvNmU9daj9V00118H9KQBozQQsZt4pyLQcZdc",
                        SignatureMethod::HMAC_SHA1);
        println!("{}", s.get_base_string("https://api.twitter.com/1.1/statuses/user_timeline.json"));
    }
}







#[derive(Clone)]
pub struct Builder {
    request_url         : String,
    consumer_key        : String,
    callback_url        : String,
    signature_method    : SignatureMethod,
    require_nonce       : bool,
    require_timestamp   : bool,
    version             : Option<String>,
    realm               : Option<String>
}

#[derive(Clone)]
pub struct TemporaryCredentials {
    request_url         : String,
    consumer_key        : String,
    callback_url        : String,
    signature_method    : SignatureMethod,
    version             : Option<String>,
    realm               : Option<String>,
    nonce               : Option<String>,
    timestamp           : Option<String>,
}

impl Builder {
    pub fn new(request_url : String, consumer_key : String, callback_url : String, signature_method : SignatureMethod) -> Builder {
        let require = match signature_method {SignatureMethod::PLAINTEXT => false, _ => true};
        Builder {
            request_url         : request_url,
            consumer_key        : consumer_key,
            callback_url        : callback_url,
            signature_method    : signature_method,
            require_nonce       : require,
            require_timestamp   : require,
            version             : None,
            realm               : None
        }
    }

    pub fn set_version(mut self)-> Builder {
        self.version = Some("1.0".to_string());
        self
    }

    pub fn set_realm(mut self, realm : String) -> Builder {
        self.realm = Some(realm);
        self
    }

    pub fn require_nonce(mut self) -> Builder {
        self.require_nonce = true;
        self
    }

    pub fn require_timestamp(mut self) -> Builder {
        self.require_timestamp = true;
        self
    }

    pub fn create(self) -> TemporaryCredentials {
        TemporaryCredentials {
            request_url         : self.request_url,
            consumer_key        : self.consumer_key,
            callback_url        : self.callback_url,
            signature_method    : self.signature_method,
            version             : self.version,
            realm               : self.realm,
            nonce               : if self.require_nonce {Some(generate_nonce())}
                                  else {None},
            timestamp           : if self.require_timestamp {Some(now_utc().to_timespec().sec.to_string())}
                                  else {None}

        }
    }
}

impl TemporaryCredentials {
    pub fn send_post_request(self)->Result<(),()>{
        Ok(())
    }
}

impl AuthorizationHeader for TemporaryCredentials {
    fn get_header(&self) -> String {
        "".to_string()
    }
}

impl fmt::Show for TemporaryCredentials {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let builder : String;

        write!(f, "output")
    }
}
