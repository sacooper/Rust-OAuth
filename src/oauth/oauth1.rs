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


#[unstable]
pub struct Session<'a> {
    oauth_consumer_key : &'a str,
    oauth_token : &'a str,
    oauth_token_secret : &'a str,
    oauth_signature_method : &'a str,
    oauth_signature : &'a str,
}

// TODO: add to crypto library?
// TODO: Should we have a longer nonce than 10?
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
    // pub fn set_realm(&mut self, realm : Option<&'a str>)->&Session<'a>{
    //     self.realm = realm;
    //     self
    // }

    pub fn get_temporary_credentials(&self) {
        // TODO
        unimplemented!();
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

fn generate_nonce() -> String {
    "".to_string()
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
            timestamp           : if self.require_timestamp {Some(time::now().to_timespec().sec.to_string())}
            else {None}

        }
    }
}

impl TemporaryCredentials {
    pub fn send_post_request(self)->Result<(),()>{
        Ok(())
    }
}

impl fmt::Show for TemporaryCredentials {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let builder : String;

        write!(f, "output")
    }
}
