//! All errors
use std::{
    error, fmt,
};

#[cfg(feature="password")] 
pub mod password;
#[cfg(feature="aes")]
pub mod aes;
