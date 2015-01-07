//! OAuth 1
//!
//!# Example
//!
//!```
//!use rust_oauth::oauth::oauth1;
//!let x = oauth1::Session::new("A","B","C");
//!println!("{}", x.oauth_token);
//!```

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

impl<'a> Session<'a> {
    pub fn new (token: &'a str, secret: &'a str, callback: &'a str) -> Session<'a> {
        Session {
            realm : None,
            oauth_token: token,
            oauth_verifier: secret,
            oauth_callback: callback,
            oauth_callback_confirmed : None,
            authorize_url : None,
            base_url : None,
            session_obj : None,
            signature_obj : None,
        }
    }
    pub fn set_realm(&self, realm : Option<&'a str>)->Session<'a>{
        Session {realm:realm, ..(*self)}
    }
    pub fn set_oauth_callback_confirmed(&self, oauth_callback_confirmed : Option<&'a str>)->Session<'a>{
        Session {oauth_callback_confirmed:oauth_callback_confirmed, ..(*self)}
    }
    pub fn set_authorize_url(&self, authorize_url : Option<&'a str>)->Session<'a>{
        Session {authorize_url:authorize_url, ..(*self)}
    }
    pub fn set_base_url(&self, base_url : Option<&'a str>)->Session<'a>{
        Session {base_url:base_url, ..(*self)}
    }
    pub fn set_session_obj(&self, session_obj : Option<&'a str>)->Session<'a>{
        Session {base_url:base_url, ..(*self)}
    }

}

#[cfg(test)]
mod tests {
    use crypto::sha1::{sha1};
    use oauth::oauth1;

    // Session initialization and setup test
    #[test]
    fn oauth1_session_test1() {
        let s = oauth1::Session::new("Token", "Secret", "Callback");
        assert!(s.oauth_token == "Token" && s.oauth_verifier == "Secret" &&
                s.oauth_callback == "Callback")
    }
}
