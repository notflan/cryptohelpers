//! Collection of helpers for cryptography things.
//! All modules are feature gated.
//!
//! * sha256 - `sha256` feature
//! * password - `password` feature
//! * aes - `aes` feature
//! * crc - `checksum` feature
//! * rsa - `rsa` feature
//!
//! There is also `full` for enabling them all.
//!
//! # Async processing
//! The `async` feature adds asynchronous streaming functions with Tokio's `AsyncRead` and `AsyncWrite` traits.

#![allow(dead_code)]

pub mod consts;
#[allow(unused_imports)]
use consts::*;

mod util;
mod bytes;

#[allow(unused_imports)]
mod error;

#[cfg(feature="serde")]
use serde_derive::{
    Serialize, Deserialize,
};

// Actual things

#[cfg(feature="sha256")] 
pub mod sha256;
#[cfg(feature="password")]
pub mod password;
#[cfg(feature="aes")]
pub mod aes;
#[cfg(feature="checksum")]
pub mod crc;
#[cfg(feature="rsa")]
pub mod rsa;
