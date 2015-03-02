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
    oauth_version : bool,
}


impl<'a> Session<'a> {
    // Creates a Session Object, which contains all reused parameters
    // for OAuth 1.0A. This is the Struct used to communicate with a server
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
            oauth_version : true,
        }
    }

    pub fn set_realm(mut self, realm: &'a str) -> Self {
        self.realm = Some(realm);
        self
    }


    /// Takes an API url, data, and HTTP Method and a closure and generates all needed
    /// OAuth parameters and sends an HTTP request using the provided closure
    pub fn request(&mut self, method: HTTPMethod, base_url: &str, data: Vec<(&str, &str)>) {
        use oauth1::client::BaseString;
        self.oauth_timestamp = generate_timestamp();
        self.oauth_nonce = generate_nonce();
        let base_string = self.get_base_string( HTTPMethod::GET, base_url, data);
        self.oauth_signature = self.generate_signature(base_string);
        println!("\n\n{}\n\n", self.oauth_signature);
    }

    pub fn generate_signature(&mut self, base_string: String) -> String {
        let key = format!("{}&{}", encode!(self.oauth_consumer_key), encode!(self.oauth_token_secret));
        self.oauth_signature_method.sign( base_string, key)
    }
}


// Creates a URL encoded String containing headers for an OAuth request
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
        if self.oauth_version {
            params.push(String::from_str("oauth_version=1.0"));
        }
        params
    }
}

#[cfg(test)]
mod tests {
    use super::{Session};
    use ::oauth1::client::{HTTPMethod, AuthorizationHeader, BaseString};
    use ::crypto::SignatureMethod;

    #[test]
    // Verifies the validity of the base string. Used the twitter OAuth signature generator
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
            oauth_version : true,
        };
        let input = vec![("screen_name", "twitterapi"), ("count", "2")];
        let base_string = s.get_base_string( HTTPMethod::GET, "https://api.twitter.com/1.1/statuses/user_timeline.json", input);
        assert!(base_string == expected_base_string);
    }

    #[test]
    /// TODO: should use example from OAuth v1 RFC
    // Session initialization and setup test
    fn base_string_rfc_p19_test() {
        let expected_base_string = "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7";
        let mut s = Session {
            oauth_consumer_key: "9djdj82h48djs9d2",
            oauth_token: "kkk9d7dh3k39sjv7",
            oauth_token_secret : "my_token",
            oauth_signature_method: SignatureMethod::HMACSHA1,
            oauth_signature: String::new(),
            oauth_timestamp: String::from_str("137131201"),
            oauth_nonce: String::from_str("7d8f3e4a"),
            realm : Some("Example"),
            oauth_version : false,
        };
        let input = vec![("c2", ""), ("a3", "2+q")];
        let base_string = s.get_base_string( HTTPMethod::POST, "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", input);
        println!("\n\n{}\n\n", base_string);
        assert!(base_string == expected_base_string);
    }

    #[test]
    // TODO
    //
    fn oauth_request_test() {
        let mut s = Session::new("k0azC44q2c0DgF7ua9YZ6Q",
                             "119544186-6YZKqkECA9Z0bxq9bA1vzzG7tfPotCml4oTySkzj",
                             "zvNmU9daj9V00118H9KQBozQQsZt4pyLQcZdc",
                             SignatureMethod::HMACSHA1);
        let input = vec![("screen_name", "twitterapi"), ("count", "2")];
        s.request( HTTPMethod::GET, "https://api.twitter.com/1.1/statuses/user_timeline.json", input);
    }
}
