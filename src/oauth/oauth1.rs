//! OAuth 1
//!
//!# Example
//! TODO

use std::default::Default;

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
    fn default() -> SignatureMethod {SignatureMethod::HMAC_SHA1}
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
