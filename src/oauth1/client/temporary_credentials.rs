use super::{AuthorizationHeader, generate_nonce, generate_timestamp};
use ::crypto::SignatureMethod;
use std::default::Default;

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
    realm               : Option<&'a str>,
    timestamp           : String,
    nonce               : String,
    signature           : String,
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
            realm               : self.realm,
            timestamp           : Default::default(),
            nonce               : Default::default(),
            signature           : Default::default(),
        }
    }
}

impl<'a> TemporaryCredentials<'a> {
    pub fn request(&mut self)->Result<(),()>{
        self.timestamp = generate_timestamp();
        self.nonce = generate_nonce();
        Ok(())
    }
}

impl<'a> AuthorizationHeader for TemporaryCredentials<'a> {
    fn get_header(&self) -> String {
        let header = format!("Authorization: OAuth {}oauth_consumer_key=\"{}\", \
                oauth_signature=\"{}\", oauth_signature_method=\"{}\", \
                oauth_version=\"1.0\"",
                match self.realm {
                    None => {Default::default()}, 
                    Some(r)=>{format!("Realm=\"{}\"", r)}},
                self.consumer_key, self.signature, self.signature_method);

        match self.signature_method {
            SignatureMethod::PLAINTEXT => header,
            _ => format!("{}, oauth_timestamp=\"{}\", oauth_nonce=\"{}\"",
                        header, self.timestamp, self.nonce)
        }
    }
}


impl <'a> super::BaseString for TemporaryCredentials<'a>{
    fn get_self_paramaters(&self) ->  Vec<String>{
        let mut params = Vec::new();
        match self.signature_method {
            SignatureMethod::PLAINTEXT  => (),
            _                           => {
                params.push(format!("oauth_timestamp={}", self.timestamp));
                params.push(format!("oauth_nonce={}", self.nonce));}};

        params.push(format!("oauth_consumer_key={}", self.consumer_key));
        params.push(format!("oauth_signature_method={}", self.signature_method));
        params
    }
}