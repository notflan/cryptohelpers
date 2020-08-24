#![allow(dead_code)]

mod consts;
use consts::*;

pub mod util;
pub mod bytes;

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
