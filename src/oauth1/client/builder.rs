use super::{AuthorizationHeader, generate_nonce, generate_timestamp};
use super::super::super::crypto::SignatureMethod;
use std::fmt;

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
            timestamp           : if self.require_timestamp {Some(generate_timestamp())}
                                  else {None}

        }
    }
}

impl TemporaryCredentials {
    pub fn send_post_request(self)->Result<(),()>{
        Ok(())
    }
}

impl AuthorizationHeader for TemporaryCredentials {
    fn get_header(&self) -> String {
        "".to_string()
    }
}

impl fmt::Debug for TemporaryCredentials {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let builder : String;

        write!(f, "output")
    }
}
