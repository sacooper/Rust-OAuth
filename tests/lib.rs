#![feature(core)]
extern crate rust_oauth;
extern crate curl;

use rust_oauth::crypto::SignatureMethod;
use rust_oauth::oauth1::client::session::Session;
use rust_oauth::oauth1::client::{HTTPMethod, AuthorizationHeader, concat};

use curl::http;
fn rust_curl_callback(session: Session, method: HTTPMethod, url: &str, data: Vec<(&str, &str)>)
                     -> http::response::Response {
    let to_pair = | (key, value) : (&str, &str) | -> String { format!("{}={}", key, value) };
    let header = session.get_header();
    println!("header:\n\n{}\n\n", header);
    // combine all data into url format (add equals signs and )
    let url_data = concat(data.into_iter().map(to_pair).collect::<Vec<String>>().as_slice(), "&");
    println!("url: \n\n{}\n\n", url_data);

    http::handle()
        .get(format!("{}?{}", url, url_data)).header("Authorization", header.as_slice())
        .exec().unwrap()
}

#[test]
fn twitter_api_rustcurl() {
    use std::str;
    let mut s = Session::new
                    (
                        "k0azC44q2c0DgF7ua9YZ6Q", // consumer_key
                        "omqK3feYaKOBgZajh7pqe5AU7oDkmTjLtf1p08ro1M", // consumer_secret
                        "119544186-6YZKqkECA9Z0bxq9bA1vzzG7tfPotCml4oTySkzj", // token
                        "zvNmU9daj9V00118H9KQBozQQsZt4pyLQcZdc", // token_secret
                        SignatureMethod::HMACSHA1 // signature_method
                    );
    let resp = s.request(HTTPMethod::GET, "https://api.twitter.com/1.1/statuses/user_timeline.json",
                         vec![("screen_name", "twitterapi"), ("count", "2")] , rust_curl_callback);
    let out = str::from_utf8(resp.get_body());
    println!("body={}\ncode={}\n", out.unwrap(), resp.get_code());
    assert!(resp.get_code() == 200);
}
