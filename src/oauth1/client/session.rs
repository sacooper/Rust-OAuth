//! OAuth 1
//!
//!# Example
//!
//! TODO

use super::url::{FORM_URLENCODED_ENCODE_SET, utf8_percent_encode};
use std::default::Default;
use super::{HTTPMethod, AuthorizationHeader, generate_nonce, generate_timestamp};
use ::crypto::SignatureMethod;

macro_rules! encode(($inp : expr ) => (
        utf8_percent_encode($inp, FORM_URLENCODED_ENCODE_SET)
    );
);

#[unstable]
pub struct Session<'a> {
    oauth_consumer_key : &'a str,
    oauth_token : &'a str,
    oauth_token_secret : &'a str,
    realm : Option<&'a str>,
    oauth_signature_method : SignatureMethod,
    oauth_signature : String,
    oauth_timestamp : String,
    oauth_nonce : String,
}


impl<'a> Session<'a> {
    // Creates a Session Object, which contains all reused parameters
    // for OAuth 1.0A. This is the Struct used to communicate with a server
    // TODO: Should we use options for oauth_nonce and oauth_timestamp?
    pub fn new (consumer_key: &'a str, token: &'a str, secret: &'a str, signature_method: SignatureMethod) -> Session<'a> {
        Session {
            oauth_consumer_key: consumer_key,
            oauth_token: token,
            oauth_token_secret : secret,
            oauth_signature_method: signature_method,
            oauth_signature: Default::default(),
            oauth_timestamp: Default::default(),
            oauth_nonce: Default::default(),
            realm : None,
        }
    }

    pub fn set_realm(mut self, realm: &'a str) -> Self {
        self.realm = Some(realm);
        self
    }


    // this function will take API url and data and use that to send an Oauth request.
    pub fn request(&mut self, method: HTTPMethod, base_url: &str, data: Vec<(&str, &str)>) {
        use oauth1::client::BaseString;
        self.oauth_timestamp = generate_timestamp();
        self.oauth_nonce = generate_nonce();
        self.oauth_signature = self.oauth_signature_method
                               .sign(self.get_base_string( HTTPMethod::GET, base_url, data),
                                     format!("{}&{}", encode!(self.oauth_consumer_key), encode!(self.oauth_token_secret)));
        println!("\n\n{}\n\n", self.oauth_signature);
    }
}


// Creates a URL encoded String containing headers
// This should be called everytime you make a request, since the
// `oauth_timestamp` and `oauth_nonce` need to freshly made
impl<'a> AuthorizationHeader for Session<'a>{
    fn get_header(&self) -> String {
        let header = format!("Authorization: OAuth {}oauth_consumer_key=\"{}\", \
                              oauth_signature=\"{}\", oauth_signature_method=\"{}\", \
                              oauth_token=\"{}\", oauth_version=\"1.0\"",
                              match self.realm {
                                  None => Default::default(),
                                  Some(r) => format!("Realm=\"{}\"", r)
                              },
                              self.oauth_consumer_key, self.oauth_signature,
                              self.oauth_signature_method, self.oauth_token
                     );

        match self.oauth_signature_method {
            SignatureMethod::PLAINTEXT => header,
            _ => format!("{}, oauth_timestamp=\"{}\", oauth_nonce=\"{}\"",
                         header, self.oauth_timestamp, self.oauth_nonce)
        }
    }
}


impl <'a> super::BaseString for Session<'a>{
    fn get_self_paramaters(&self) ->  Vec<String>{
        let mut params = Vec::new();

        match self.oauth_signature_method {
            SignatureMethod::PLAINTEXT  => (),
            _                           => {
                params.push(format!("oauth_timestamp={}", self.oauth_timestamp));
                params.push(format!("oauth_nonce={}", self.oauth_nonce));
            }
        };

        params.push(format!("oauth_consumer_key={}", self.oauth_consumer_key));
        params.push(format!("oauth_signature_method={}", self.oauth_signature_method));
        params.push(format!("oauth_token={}", self.oauth_token));
        params.push(String::from_str("oauth_version=1.0"));
        params
    }
}

#[cfg(test)]
mod tests {
    use super::{Session};
    use super::super::{HTTPMethod, AuthorizationHeader, BaseString};
    use ::crypto::SignatureMethod;

    #[test]
    // Verifies the validity of the base string. Used the twitter oauth signature generator
    // which can be [found here](https://dev.twitter.com/oauth/tools/signature-generator/4128189?nid=731)
    fn base_string_test() {
        let expected_base_string = "GET&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fuser_timeline.json&count%3D2%26oauth_consumer_key%3Dk0azC44q2c0DgF7ua9YZ6Q%26oauth_nonce%3Db9114cda0b95170ff9b164d8226c4b07%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1425071144%26oauth_token%3D119544186-6YZKqkECA9Z0bxq9bA1vzzG7tfPotCml4oTySkzj%26oauth_version%3D1.0%26screen_name%3Dtwitterapi";
        let mut s = Session {
            oauth_consumer_key: "k0azC44q2c0DgF7ua9YZ6Q",
            oauth_token: "119544186-6YZKqkECA9Z0bxq9bA1vzzG7tfPotCml4oTySkzj",
            oauth_token_secret : "zvNmU9daj9V00118H9KQBozQQsZt4pyLQcZdc",
            oauth_signature_method: SignatureMethod::HMACSHA1,
            oauth_signature: String::new(),
            oauth_timestamp: String::from_str("1425071144"),
            oauth_nonce: String::from_str("b9114cda0b95170ff9b164d8226c4b07"),
            realm : None,
        };
        let input = vec![("screen_name", "twitterapi"), ("count", "2")];
        let base_string = s.get_base_string( HTTPMethod::GET, "https://api.twitter.com/1.1/statuses/user_timeline.json", input);
        println!("\n\n{}\n\n", base_string);
        assert!(base_string == expected_base_string);
    }

    /// TODO: should use example from OAuth v1 RFC
    // Session initialization and setup test
    #[test]
    fn hw() {
        let mut s = Session::new("k0azC44q2c0DgF7ua9YZ6Q",
                             "119544186-6YZKqkECA9Z0bxq9bA1vzzG7tfPotCml4oTySkzj",
                             "zvNmU9daj9V00118H9KQBozQQsZt4pyLQcZdc",
                             SignatureMethod::HMACSHA1);
        let input = vec![("screen_name", "twitterapi"), ("count", "2")];
        s.request( HTTPMethod::GET, "https://api.twitter.com/1.1/statuses/user_timeline.json", input);
    }
}
