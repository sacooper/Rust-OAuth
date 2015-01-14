//! OAuth 1
//!
//!# Example
//!
//! TODO

use std::default::Default;

pub struct Session<'a> {
    oauth_token : &'a str,
    oauth_verifier : &'a str,
    request_token_url : &'a str,
    realm : Option<&'a str>,
    oauth_consumer_key : Option<&'a str>,
    oauth_signature : Option<&'a str>,
    oauth_signature_method : Option<&'a str>,
    oauth_callback_confirmed : Option<&'a str>,
    oauth_token_secret : Option<&'a str>,
    temporary_credentials_url : Option<&'a str>,
    callback_token_url : Option<&'a str>,
}

impl<'a> Default for Session<'a> {
    fn default() -> Session<'a> {
        Session {
            oauth_token: "",
            oauth_verifier: "",
            request_token_url: "",
            realm: None,
            oauth_consumer_key: None,
            oauth_signature: None,
            oauth_signature_method: None,
            oauth_callback_confirmed: None,
            oauth_token_secret: None,
            temporary_credentials_url: None,
            callback_token_url: None,

        }
    }
}
impl<'a> Session<'a> {
    pub fn new (token: &'a str, secret: &'a str, request_token_url: &'a str) -> Session<'a> {
        Session {
            oauth_token: token,
            oauth_verifier: secret,
            request_token_url: request_token_url,
            ..Default::default()
        }
    }
    pub fn get_temporary_credentials(&self) {

    }
}

#[cfg(test)]
mod tests {
    use oauth::oauth1::Session;

    // Session initialization and setup test
    #[test]
    fn hw() {
        let s = Session::new("Token", "Secret", "https://api.twitter.com/oauth/request_token");
    }
}
