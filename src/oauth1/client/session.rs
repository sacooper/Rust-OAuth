//! Holds all parameters needed to make OAuth requests
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
    oauth_consumer_secret : &'a str,
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
    /// Creates a Session Object, which contains all reused parameters
    /// for OAuth 1.0A. This is the Struct used to communicate with a server
    pub fn new (consumer_key: &'a str, consumer_secret: &'a str, token: &'a str,
                token_secret: &'a str, signature_method: SignatureMethod) -> Session<'a> {
        Session {
            oauth_consumer_key: consumer_key,
            oauth_consumer_secret: consumer_secret,
            oauth_token: token,
            oauth_token_secret: token_secret,
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
    pub fn request<T, F>(&mut self, method: HTTPMethod, base_url: &str,
                    data: Vec<(&str, &str)>, callback: F) -> T
                    where F: Fn(Session, HTTPMethod, &str, Vec<(&str, &str)>) -> T {
        use oauth1::client::BaseString;
        self.oauth_timestamp = generate_timestamp();
        self.oauth_nonce = generate_nonce();
        let base_string = self.get_base_string(HTTPMethod::GET, base_url, data.clone());
        self.oauth_signature = self.generate_signature(base_string);
        callback(self.clone(), method, base_url, data)
    }

    pub fn generate_signature(&mut self, base_string: String) -> String {
        let key = format!("{}&{}", encode!(self.oauth_consumer_secret), encode!(self.oauth_token_secret));
        encode!(self.oauth_signature_method.sign( base_string, key).as_slice())
    }
}


/// Creates a URL encoded String containing headers formated for an OAuth request
impl<'a> AuthorizationHeader for Session<'a> {
    fn get_header(&self) -> String {
        let header = format!("OAuth {}oauth_consumer_key=\"{}\", \
                              oauth_signature=\"{}\", oauth_signature_method=\"{}\", \
                              oauth_token=\"{}\", oauth_version=\"1.0\"",
                              match self.realm {
                                  None => Default::default(),
                                  Some(r) => format!("realm=\"{}\", ", r)
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

impl<'a>  Clone for Session<'a>  {
    fn clone(&self) -> Self {
        Session {
            oauth_consumer_key: self.oauth_consumer_key,
            oauth_consumer_secret: self.oauth_consumer_secret,
            oauth_token: self.oauth_token,
            oauth_token_secret: self.oauth_token_secret,
            oauth_signature_method: self.oauth_signature_method,
            oauth_signature: self.oauth_signature.clone(),
            oauth_timestamp: self.oauth_timestamp.clone(),
            oauth_nonce: self.oauth_nonce.clone(),
            realm : self.realm,
            oauth_version : self.oauth_version,
        }
    }
}


impl <'a> super::BaseString for Session<'a> {
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
    use oauth1::client::url::{FORM_URLENCODED_ENCODE_SET, utf8_percent_encode};
    use ::crypto::SignatureMethod;

    #[test]
    /// Verifies the validity of the base string. Used the twitter OAuth signature generator
    /// which can be [found here](https://dev.twitter.com/oauth/tools/signature-generator/4128189?nid=731)
    fn base_string_twitter_test() {
        let expected_base_string = "GET&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fuser_timeline.json&count%3D2%26oauth_consumer_key%3Dk0azC44q2c0DgF7ua9YZ6Q%26oauth_nonce%3Db9114cda0b95170ff9b164d8226c4b07%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1425071144%26oauth_token%3D119544186-6YZKqkECA9Z0bxq9bA1vzzG7tfPotCml4oTySkzj%26oauth_version%3D1.0%26screen_name%3Dtwitterapi";
        let s = Session {
            oauth_consumer_key: "k0azC44q2c0DgF7ua9YZ6Q",
            oauth_consumer_secret: "omqK3feYaKOBgZajh7pqe5AU7oDkmTjLtf1p08ro1M",
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
    /// Session initialization and setup test. Uses an example from [RFC5849 3.4.1]
    /// (https://tools.ietf.org/html/rfc5849#section-3.4.1)
    fn base_string_rfc_test() {
        let expected_base_string = "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7";
        let s = Session {
            oauth_consumer_key: "9djdj82h48djs9d2",
            oauth_consumer_secret: "j49sk3j29djd",
            oauth_token: "kkk9d7dh3k39sjv7",
            oauth_token_secret : "dh893hdasih9",
            oauth_signature_method: SignatureMethod::HMACSHA1,
            oauth_signature: String::new(),
            oauth_timestamp: String::from_str("137131201"),
            oauth_nonce: String::from_str("7d8f3e4a"),
            realm : Some("Example"),
            oauth_version : false,
        };
        let input = vec![("c2", ""), ("a3", "2+q")];
        let base_string = s.get_base_string( HTTPMethod::POST, "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", input);
        assert!(base_string == expected_base_string);
    }

    #[test]
    /// Verifies that the signature is properly generated. Uses the [example from
    /// twitter](https://dev.twitter.com/oauth/overview/creating-signatures) as a test case
    fn hmac_sha1_signature_test() {
        let expected_signature = String::from_str("tnnArxj06cWHq44gCs1OSKk/jLY=");
        let message = "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521";
        let key = format!("{}&{}", encode!("kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw"),
                                   encode!("LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"));
        let signature = SignatureMethod::HMACSHA1.sign(message.to_string(), key);
        assert!(signature == expected_signature);
    }

    #[test]
    /// Verifies that the OAuth header contains all needed values
    fn oauth_header_test() {
        let s = Session {
            oauth_consumer_key: "9djdj82h48djs9d2",
            oauth_consumer_secret: "j49sk3j29djd",
            oauth_token: "kkk9d7dh3k39sjv7",
            oauth_token_secret : "dh893hdasih9",
            oauth_signature_method: SignatureMethod::HMACSHA1,
            oauth_signature: String::from_str("bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"),
            oauth_timestamp: String::from_str("137131201"),
            oauth_nonce: String::from_str("7d8f3e4a"),
            realm : Some("Example"),
            oauth_version : false,
        };
        let header = s.get_header();

        assert!(header.starts_with("OAuth"));
        assert!(header.contains("realm=\"Example\""));
        assert!(header.contains("oauth_consumer_key=\"9djdj82h48djs9d2\""));
        assert!(header.contains("oauth_token=\"kkk9d7dh3k39sjv7\""));
        assert!(header.contains("oauth_signature_method=\"HMAC-SHA1\""));
        assert!(header.contains("oauth_timestamp=\"137131201\""));
        assert!(header.contains("oauth_nonce=\"7d8f3e4a\""));
        assert!(header.contains("oauth_signature=\"bYT5CMsGcbgUdFHObYMEfcx6bsw%3D\""))
    }

    #[test]
    /// Full OAuth generation tests. Uses the twitter OAuth signature generator
    /// which can be [found here](https://dev.twitter.com/oauth/tools/signature-generator/4128189?nid=731)
    fn oauth_full_flow_twitter_test() {
        let expected_base_string = "GET&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fuser_timeline.json&count%3D2%26oauth_consumer_key%3Dk0azC44q2c0DgF7ua9YZ6Q%26oauth_nonce%3Dbfa380dd4f1aadc18145c1385130305b%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1425427447%26oauth_token%3D119544186-6YZKqkECA9Z0bxq9bA1vzzG7tfPotCml4oTySkzj%26oauth_version%3D1.0%26screen_name%3Dtwitterapi";
        let expected_oauth_signature = "BJPEhpBgsJ4WlBDp7v%2BvKp9pTB8%3D";

        let input = vec![("screen_name", "twitterapi"), ("count", "2")];
        let mut s = Session {
            oauth_consumer_key: "k0azC44q2c0DgF7ua9YZ6Q",
            oauth_consumer_secret: "omqK3feYaKOBgZajh7pqe5AU7oDkmTjLtf1p08ro1M",
            oauth_token: "119544186-6YZKqkECA9Z0bxq9bA1vzzG7tfPotCml4oTySkzj",
            oauth_token_secret : "zvNmU9daj9V00118H9KQBozQQsZt4pyLQcZdc",
            oauth_signature_method: SignatureMethod::HMACSHA1,
            oauth_signature: String::new(),
            oauth_timestamp: String::from_str("1425427447"),
            oauth_nonce: String::from_str("bfa380dd4f1aadc18145c1385130305b"),
            realm : None,
            oauth_version : true,
        };
        let base_string = s.get_base_string( HTTPMethod::GET, "https://api.twitter.com/1.1/statuses/user_timeline.json", input);
        assert!(base_string == expected_base_string);

        let signature = s.generate_signature(base_string);
        assert!(signature == expected_oauth_signature);
    }
}
