#![allow(dead_code)]

pub mod consts;
#[allow(unused_imports)]
use consts::*;

pub mod util;
pub mod bytes;

#[allow(unused_imports)]
mod error;

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
