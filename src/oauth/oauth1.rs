
pub struct Session<'a> {
    consumer_key : &'a str,
    consumer_secret : &'a str,
/*
    name : String,
    request_token_url : String,
    access_token_url : String,
    authorize_url : String,
    base_url : String,
    session_obj : String,
    signature_obj : String,
*/
}

impl<'a> Session<'a> {
    pub fn new (consumer_key: &'a str, consumer_secret: &'a str) -> Session<'a> {
        Session {
            consumer_key: consumer_key,
            consumer_secret: consumer_secret
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
        let s = oauth1::Session::new("Hello", "World");
    }
}
