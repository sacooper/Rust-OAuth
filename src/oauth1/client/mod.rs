extern crate time;
extern crate url;
extern crate rand;

use self::url::{FORM_URLENCODED_ENCODE_SET, utf8_percent_encode};
use self::time::now_utc;
use self::rand::{OsRng, Rng};
use std::fmt;

pub mod session;
pub mod temporary_credentials;

#[derive(Copy, Debug, PartialEq, Eq, Clone)]
#[unstable]
pub enum HTTPMethod {
    GET,
    POST,
    DELETE,
    PUT,
    HEAD
}

impl fmt::Display for HTTPMethod {
    fn fmt(&self, f : &mut fmt::Formatter) -> fmt::Result{
        let out = match *self {
            HTTPMethod::GET     => "GET",
            HTTPMethod::POST    => "POST",
            HTTPMethod::DELETE  => "DELETE",
            HTTPMethod::PUT     => "PUT",
            HTTPMethod::HEAD    => "HEAD"
        };
        write!(f, "{}", out)
    }
}


pub trait AuthorizationHeader {
    fn get_header(&self) -> String;
}

// TODO: add to crypto library?
fn generate_nonce() -> String {
    OsRng::new().unwrap()
                .gen_ascii_chars()
                .take(32)
                .collect()
}

fn generate_timestamp() -> String {
    now_utc().to_timespec().sec.to_string()
}

pub trait BaseString {
    /// Returns a base string URI, ecnoded with [RFC3986]. This gets used to
    /// generate the `oauth_signature`. It takes a different path dependent
    /// on the signature type
    fn get_base_string(&self, method: HTTPMethod, base_url: &str, data: Vec<(&str, &str)>) -> String {
        // split URL at `?`, to sort parameters
        let split_url : Vec<&str> = base_url.rsplitn(1, '?').collect();
        let (url, url_data) = match split_url.len() {
            1 => (Some(split_url[0]), None),                // no parameters in the request url
            2 => (Some(split_url[1]), Some(split_url[0])),  // if there are parameters
            _ => (None, None)                               // erronous input base_url
        };
        format!("{}&{}&{}", method,
                utf8_percent_encode(url.unwrap(), FORM_URLENCODED_ENCODE_SET),
                utf8_percent_encode(self.get_base_parameters(data, url_data).as_slice(), FORM_URLENCODED_ENCODE_SET))
    }
    /// Returns all the required parameters used in the OAuth request. It takes into account
    /// the signature method as well as which type of OAuth request you are making
    fn get_self_paramaters(&self) -> Vec<String>;

    /// Takes the required OAuth `self_parameters` and the input data and returns a String with
    /// all parameters in alphabetical order
    fn get_base_parameters(&self, data: Vec<(&str, &str)>, url_data : Option<&str>) -> String {
        let to_pair = | (key, value) : (&str, &str) | -> String { format!("{}={}", key, value) };

        let mut params = self.get_self_paramaters();
        params.append(&mut (data.into_iter().map(to_pair).collect::<Vec<String>>()));
        match url_data {
            None => {}
            Some(r) => {
                params.append(&mut r.split('&').map(|val : &str| -> String {val.to_string()}).collect());
            },
        };
        params.sort();
        // TODO: add a new url-encoding method to do the equivalent
        concat(params.as_slice(), "&").replace("+", "%20")
                                      .replace("*","%2A")
    }
}


/// Concatenate all values in `data`, seperated by `sep`
///
/// ```
/// use rust_oauth::oauth1::client::concat;
/// let values = vec!["cat".to_string(), "dog".to_string(), "bird".to_string()];
/// let concatenated = concat(values.as_slice(), " ");
/// assert_eq!(concatenated, "cat dog bird".to_string());
/// ```
pub fn concat(data: &[String], sep : &str) -> String {
    match data {
        []              => String::new(),
        [ref param]         => format!("{}", param),
        [ref param, rest..]  => format!("{}{}{}", param, sep, concat(rest, sep))
    }
}


#[cfg(test)]
mod test {
    use super::{concat, generate_nonce};

    #[test]
    fn concat_test_multiple_items() {
        let data = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
        assert_eq!(concat(data.as_slice(), "&"), "alpha&beta&gamma".to_string())
    }

    #[test]
    fn concat_test_empty_vec() {
        let data = vec![];
        assert_eq!(concat(data.as_slice(), "&"), String::new())
    }

    #[test]
    fn concat_test_single() {
        let data = vec!["alpha".to_string()];
        assert_eq!(concat(data.as_slice(), "&"), "alpha".to_string())
    }

    #[test]
    fn generate_nonce_unique(){
        let mut nonces = Vec::new();
        for _ in 0..1000 {
            nonces.push(generate_nonce())
        }
        let len = nonces.len();
        nonces.dedup();
        assert_eq!(len, nonces.len());
    }
}
