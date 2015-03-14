[![](https://travis-ci.org/sacooper/Rust-OAuth.svg?branch=master)](https://travis-ci.org/sacooper/Rust-OAuth)

Rust-OAuth
==========

Currently, an implementation of OAuth protocol v1.0A. We plan to add OAuth 2.0 support in the near future

Usage
-----
Because `rust_oauth` is http-library agnositc, you need to use a callback function to send a request.
For the sake of brevity, only this example will only work with the `curl` library.
There are more examples in [tests/lib.rs](./tests/lib.rs)
```rust
extern crate rust_oauth;
extern crate curl;

fn main() {
    use std::str;
    let mut s = Session::new
                    (
                        "k0azC44q2c0DgF7ua9YZ6Q", // consumer_key
                        "omqK3feYaKOBgZajh7pqe5AU7oDkmTjLtf1p08ro1M", // consumer_secret
                        "119544186-6YZKqkECA9Z0bxq9bA1vzzG7tfPotCml4oTySkzj", // token
                        "zvNmU9daj9V00118H9KQBozQQsZt4pyLQcZdc", // token_secret
                        SignatureMethod::HMACSHA1, // signature_method
                        rust_curl_callback, // found in [tests/lib.rs]
                    );
    let resp = s.request(HTTPMethod::GET, "https://api.twitter.com/1.1/statuses/user_timeline.json",
                         vec![("screen_name", "twitterapi"), ("count", "2")]);
    println!("{}", str::from_utf8(resp.get_body()));
    //[
    //    {
    //        "created_at":"Mon Feb 02 23:13:24 +0000 2015",
    //        "id":562388344962052096,
    //        "id_str":"562388344962052096",
    //        ...
    //    }
    //]
}

use curl::http;
use rust_oauth::crypto::SignatureMethod;
use rust_oauth::oauth1::client::session::Session;
use rust_oauth::oauth1::client::{HTTPMethod, AuthorizationHeader, concat};
fn rust_curl_callback(session: Session<http::response::Response>, method: HTTPMethod,
                      url: &str, data: Vec<(&str, &str)>) -> http::response::Response {
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

```
Features
--------

- Simplify sending OAuth 1.0A requests with any http library
  - We've taken care of signing requests and creating a header
  - Provide a url, data and a callback function and you're good to go!

Installation
------------

Use `rust_oauth` by adding the following to your `Cargo.toml`
```toml
[dependencies.rust_oauth]
git = "https://github.com/sacooper/Rust-OAuth.git"
```

Contribute
----------
- Issue Tracker: https://github.com/sacooper/Rust-OAuth/issues
- Source Code: https://github.com/sacooper/Rust-OAuth
- Have any ideas? Add an issue on github!

Support
-------

If you are having problems, please add an issue on github

License
-------

The project is released under the MIT license

[readme template](http://docs.writethedocs.org/writing/beginners-guide-to-docs/#id1)
