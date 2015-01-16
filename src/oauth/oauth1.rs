//! OAuth 1
//!
//!# Example
//!
//! TODO

use std::default::Default;
use time;
use std::fmt;

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
    oauth_token : &'a str,
    oauth_verifier : &'a str,
    request_token_url : &'a str,
    oauth_consumer_key : &'a str,
    oauth_signature_method : SignatureMethod,
    realm : Option<&'a str>,
    oauth_signature : Option<&'a str>,
    callback_token_url : Option<&'a str>,
    oauth_callback_confirmed : Option<bool>,
    oauth_token_secret : Option<&'a str>,
    temporary_credentials_url : Option<&'a str>,
}

impl<'a> Session<'a> {
    pub fn new (token: &'a str, secret: &'a str, request_token_url: &'a str, consumer_key : &'a str) -> Session<'a> {
        Session {
            oauth_token: token,
            oauth_verifier: secret,
            request_token_url: request_token_url,
            oauth_consumer_key: consumer_key,
            oauth_signature_method: Default::default(),
            realm: None,
            oauth_signature: None,
            oauth_callback_confirmed: None,
            oauth_token_secret: None,
            temporary_credentials_url: None,
            callback_token_url: None,
        }
    }

    pub fn with_signature_method (token: &'a str, secret: &'a str, request_token_url: &'a str, signature_method : SignatureMethod, consumer_key : &'a str) -> Session<'a> {
        Session {
            oauth_token: token,
            oauth_verifier: secret,
            request_token_url: request_token_url,
            oauth_consumer_key: consumer_key,
            oauth_signature_method: signature_method,
            realm: None,
            oauth_signature: None,
            oauth_callback_confirmed: None,
            oauth_token_secret: None,
            temporary_credentials_url: None,
            callback_token_url: None,
        }
    }
    pub fn set_realm(&mut self, realm : Option<&'a str>)->&Session<'a>{
        self.realm = realm;
        self
    }

    pub fn get_temporary_credentials(&self) {
        // TODO
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use oauth::oauth1::Session;

    // Session initialization and setup test
    #[test]
    fn oauth1_session_test1() {
        let s = Session::new("Token", "Secret", "Callback", "ConsumerKey");
        assert!(s.oauth_token == "Token" && s.oauth_verifier == "Secret" &&
                s.request_token_url == "Callback")
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
