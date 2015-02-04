use super::{AuthorizationHeader, generate_nonce, generate_timestamp};
use super::super::super::crypto::SignatureMethod;
use std::fmt;

#[derive(Clone)]
pub struct Builder<'a> {
    request_url         : &'a str,
    consumer_key        : &'a str,
    callback_url        : &'a str,
    signature_method    : SignatureMethod,
    version             : Option<&'a str>,
    realm               : Option<&'a str>
}

#[derive(Clone)]
pub struct TemporaryCredentials<'a> {
    request_url         : &'a str,
    consumer_key        : &'a str,
    callback_url        : &'a str,
    signature_method    : SignatureMethod,
    version             : Option<&'a str>,
    realm               : Option<&'a str>
}

impl<'a> Builder<'a> {
    pub fn new(request_url : &'a str, consumer_key : &'a str, callback_url : &'a str, signature_method : SignatureMethod) -> Builder<'a> {
        Builder {
            request_url         : request_url,
            consumer_key        : consumer_key,
            callback_url        : callback_url,
            signature_method    : signature_method,
            version             : None,
            realm               : None
        }
    }

    pub fn use_version(mut self)-> Builder<'a> {
        self.version = Some("1.0");
        self
    }

    pub fn set_realm(mut self, realm : &'a str) -> Builder<'a> {
        self.realm = Some(realm);
        self
    }

    pub fn create(self) -> TemporaryCredentials<'a> {
        TemporaryCredentials {
            request_url         : self.request_url,
            consumer_key        : self.consumer_key,
            callback_url        : self.callback_url,
            signature_method    : self.signature_method,
            version             : self.version,
            realm               : self.realm
        }
    }
}

impl<'a> TemporaryCredentials<'a> {
    pub fn send_post_request(self)->Result<(),()>{
        Ok(())
    }
}

impl<'a> AuthorizationHeader for TemporaryCredentials<'a> {
    fn get_header(&self) -> String {
        "".to_string()
    }
}

impl<'a> fmt::Debug for TemporaryCredentials<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let builder : String;

        write!(f, "output")
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
