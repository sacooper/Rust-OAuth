//! OAuth 1
//!
//!# Example
//!
//! TODO
extern crate url;
use self::url::percent_encoding::{utf8_percent_encode, FORM_URLENCODED_ENCODE_SET};
use std::default::Default;
use std::fmt;
use super::{HTTPMethod, AuthorizationHeader, generate_nonce, generate_timestamp};
use super::super::super::crypto::SignatureMethod;
impl Default for SignatureMethod {
    fn default() -> SignatureMethod {
        SignatureMethod::HMAC_SHA1}
}

struct ParamTuple<'a>((&'a str, &'a str));

impl<'a> fmt::Display for ParamTuple<'a> {
    fn fmt(&self, f : &mut fmt::Formatter) -> fmt::Result {
        let &ParamTuple((key, value)) = self;
        write!(f, "&{}={}", key, value)
    }
}

fn to_parameters(data: &[String]) -> String {
    match data {
        []              => String::new(),
        [ref param]         => format!("{}", param),
        [ref param, rest..]  => format!("{}&{}", param, to_parameters(rest))
    }
}

#[unstable]
pub struct Session<'a> {
    oauth_consumer_key : &'a str,
    oauth_token : &'a str,
    oauth_token_secret : &'a str,
    oauth_signature_method : SignatureMethod,
    oauth_signature : String,
    oauth_timestamp : String,
    oauth_nonce : String,
}


impl<'a> Session<'a> {
    // Creates a Session Object, which contains all reused parameters
    // for OAuth 1.0A. This is the Struct used to communicate with a server
    // TODO: Should we use options for oauth_nonce and oauth_timestamp?
    pub fn new (consumer_key: &'a str, token: &'a str, secret: &'a str,
                signature_method: SignatureMethod) -> Session<'a> {
        Session {
            oauth_consumer_key: consumer_key,
            oauth_token: token,
            oauth_token_secret : secret,
            oauth_signature_method: signature_method,
            oauth_signature: Default::default(),
            oauth_timestamp: Default::default(),
            oauth_nonce: Default::default(),
        }
    }
    // Returns a base string URI, ecnoded with [RFC3986]. This gets used to
    // generate the `oauth_signature`. It takes a different path dependent
    // on the signature type
    fn get_base_string(self, method: HTTPMethod, base_url: &'a str, data: Vec<(&str, &str)>) -> String {
        format!("{}&{}&{}", method,
                utf8_percent_encode(base_url.as_slice(), FORM_URLENCODED_ENCODE_SET),
                utf8_percent_encode(self.get_base_parameters(data).as_slice(), FORM_URLENCODED_ENCODE_SET))
    }

    fn get_base_parameters(mut self, mut data: Vec<(&str, &str)>) -> String {
        let mut params = Vec::new();

        match self.oauth_signature_method {
            SignatureMethod::PLAINTEXT  => (),
            _                           => {
                params.push(format!("oauth_timestamp={}", generate_timestamp()));
                params.push(format!("oauth_nonce={}", generate_nonce()));}};

        let to_pairs = |&: (key, value) : (&str, &str) | -> String {
            format!("{}={}", key, value)};

        params.push(format!("oauth_consumer_key={}", self.oauth_consumer_key));
        params.push(format!("oauth_signature_method={}", self.oauth_signature_method));
        params.push(format!("oauth_token={}", self.oauth_token));
        params.append(&mut (data.into_iter().map(to_pairs).collect::<Vec<String>>()));
        params.sort();
        to_parameters(params.as_slice())
    }

    #[unimplemented]
    // this function will take API url and data and use that to send
    // an Oauth request. Data shouldn't need to be in alphabetical order
    // but will be in it's own data structure.
    fn request(&self, base_url: String) {

    }
}


// Creates a URL encoded String containing headers
// This should be called everytime you make a request, since the
// `oauth_timestamp` and `oauth_nonce` need to freshly made
impl<'a> AuthorizationHeader for Session<'a>{
    fn get_header(&self) -> String {
        let header = format!("Authorization: OAuth oauth_consumer_key=\"{}\", \
                        oauth_signature=\"{}\", oauth_signature_method=\"{}\", \
                        oauth_token=\"{}\", oauth_version=\"1.0\"",
                        self.oauth_consumer_key, self.oauth_signature,
                        self.oauth_signature_method, self.oauth_token);

        match self.oauth_signature_method {
            SignatureMethod::PLAINTEXT => header,
            _ => format!("{}, oauth_timestamp=\"{}\", oauth_nonce=\"{}\"",
                        header, self.oauth_timestamp, self.oauth_nonce)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Session, to_parameters};
    use super::super::{HTTPMethod, AuthorizationHeader};
    use ::crypto::SignatureMethod;

    /// TODO: should use example from OAuth v1 RFC

    // Session initialization and setup test
    #[test]
    fn hw() {
        let s = Session::new("k0azC44q2c0DgF7ua9YZ6Q",
                            "119544186-6YZKqkECA9Z0bxq9bA1vzzG7tfPotCml4oTySkzj",
                            "zvNmU9daj9V00118H9KQBozQQsZt4pyLQcZdc",
                            SignatureMethod::HMAC_SHA1);
        let base_string = s.get_base_string( HTTPMethod::GET,
                            "https://api.twitter.com/1.1/statuses/user_timeline.json",
                            vec![("screen_name", "twitterapi"),
                                 ("count", "2")]);
        // println!("{}", base_string);
    }

    #[test]
    fn to_parameters_test() {
        let to_pairs = |&: (key, value) : (&str, &str) | -> String {
            format!("{}={}", key, value)};

        let data = vec![("b", "test"), ("cat", "dog"), ("a", "hello")];
        let mut s = data.into_iter().map(to_pairs).collect::<Vec<String>>();
        s.sort();
        assert!(to_parameters(s.as_slice()) == "a=hello&b=test&cat=dog".to_string())
    }
}
