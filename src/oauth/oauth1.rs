//! OAuth 1
//!
//!# Example
//!
//!```
//!use rust_oauth::oauth::oauth1;
//!let x = oauth1::Session::new("A","B","C");
//!println!("{}", x.oauth_token);
//!```

use std::default::Default;

pub struct Session<'a> {
    realm : Option<&'a str>,
    oauth_token : &'a str,
    oauth_verifier : &'a str,
    oauth_callback : &'a str,
    oauth_callback_confirmed : Option<&'a str>,
    authorize_url : Option<&'a str>,
    base_url : Option<&'a str>,
    session_obj : Option<&'a str>,
    signature_obj : Option<&'a str>,
}

impl<'a> Default for Session<'a> {
    fn default() -> Session<'a> {
        Session {
            realm: None,
            oauth_token : "",
            oauth_verifier : "",
            oauth_callback : "",
            oauth_callback_confirmed : None,
            authorize_url : None,
            base_url : None,
            session_obj : None,
            signature_obj : None,
        }
    }
}

impl<'a> Session<'a> {
    pub fn new (token: &'a str, secret: &'a str, callback: &'a str) -> Session<'a> {
        Session {
            oauth_token: token,
            oauth_verifier: secret,
            oauth_callback: callback,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto::sha1::{sha1};
    use oauth::oauth1;

    // Session initialization and setup test
    #[test]
    fn hw() {
        let s = oauth1::Session::new("Token", "Secret", "Callback");
    }
}
