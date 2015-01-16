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
    /// HMAC-SHA1
    HMAC_SHA1,
    /// RSA-SHA1
    RSA_SHA1,
    /// PLAINTEXT
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

/// A generic trait for retrieving the authorization header from a value
pub trait AuthorizationHeader {
    fn get_header(&self) -> String;
}

#[unstable]
pub struct Session<'a> {
    oauth_consumer_key : &'a str,
    oauth_token : &'a str,
    oauth_token_secret : &'a str,
    oauth_signature_method : SignatureMethod,
    oauth_signature : &'a str,
}

// TODO: add to crypto library?
// TODO: Should we have a longer nonce than 10?
fn generate_nonce() -> String {
    thread_rng().gen_ascii_chars()
                .take(10)
                .collect()
}

impl<'a> Session<'a> {
    pub fn new (consumer_key: &'a str, token: &'a str, secret: &'a str,
                signature_method: SignatureMethod) -> Session<'a> {
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
}

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
            header, now_utc().to_timespec().sec, generate_nonce())
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
        println!("{}", s.get_header());
    }
}






#[derive(Clone)]
pub struct Builder<'a> {
    request_url         : &'a str,
    consumer_key        : &'a str,
    callback_url        : &'a str,
    signature_method    : SignatureMethod,
    require_nonce       : bool,
    require_timestamp   : bool,
    realm               : Option<&'a str>
}

impl<'a> Builder<'a> {
    pub fn new(request_url : &'a str, consumer_key : &'a str, callback_url : &'a str, signature_method : SignatureMethod) -> Builder<'a> {
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

    pub fn set_realm(mut self, realm : &'a str) -> Builder<'a> {
        self.realm = Some(realm);
        self
    }

    pub fn require_nonce(mut self) -> Builder<'a> {
        self.require_nonce = true;
        self
    }

    pub fn require_timestamp(mut self) -> Builder<'a> {
        self.require_timestamp = true;
        self
    }

    pub fn create(self) -> TemporaryCredentialsRequest<'a> {
        TemporaryCredentialsRequest {
            request_url         : self.request_url,
            consumer_key        : self.consumer_key,
            callback_url        : self.callback_url,
            signature_method    : self.signature_method,
            realm               : self.realm,
            require_nonce       : self.require_nonce,
            require_timestamp   : self.require_timestamp

        }
    }
}

#[derive(Clone)]
pub struct TemporaryCredentialsRequest<'a> {
    request_url         : &'a str,
    consumer_key        : &'a str,
    callback_url        : &'a str,
    signature_method    : SignatureMethod,
    realm               : Option<&'a str>,
    require_nonce       : bool,
    require_timestamp   : bool
}

impl<'a> TemporaryCredentialsRequest<'a> {
    pub fn get_temporary_credentials(self)->Result<TemporaryCredentials,()>{
        Ok(TemporaryCredentials{oauth_token: Default::default(), oauth_token_secret: Default::default()})
    }
}

impl<'a> AuthorizationHeader for TemporaryCredentialsRequest<'a> {
    fn get_header(&self) -> String {
        Default::default()
    }
}

#[derive(Clone)]
pub struct TemporaryCredentials {
    oauth_token        : String,
    oauth_token_secret : String
}
