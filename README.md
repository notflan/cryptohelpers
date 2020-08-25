# cryptohelpers

Collection of helpers and simplifying functions for cryptography things.
All modules are feature gated.

* sha256 - `sha256` feature
* password - `password` feature
* aes - `aes` feature
* crc - `checksum` feature
* rsa - `rsa` feature

There is also `full` for enabling them all.

## Async processing
The `async` feature adds asynchronous streaming functions with Tokio's `AsyncRead` and `AsyncWrite` traits.

# License
MIT
