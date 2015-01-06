# Proposed Structure for Rust-OAuth
Note that this initial structure only contains OAuth v1. Once v1 has been completed, this library will be refactored
to allow for any shared components between v1 and v2.

- oauth
    - client
    - server
    - common
        - signature_type
        - sign(signature_type, msg, key option)
        - common functions/structs/traits
