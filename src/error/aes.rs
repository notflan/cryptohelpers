//! AES errors
use std::{
    io,
    fmt,
    error,
    
};
use openssl::{
    error::ErrorStack,
};

#[derive(Debug)]
pub enum Error
{
    Encrypt,
    Decrypt,
    Internal(ErrorStack),
    IO(io::Error),
    Random,

    Length{expected: Option<usize>, got: Option<usize>},
    
    Unknown,
}

impl error::Error for Error
{
    fn source(&self) -> Option<&(dyn error::Error+'static)>
    {
	match &self {
	    Error::Internal(stack) => Some(stack),
	    Error::IO(io) => Some(io),
	    _ => None,
	}
    }
}
impl fmt::Display for Error
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	write!(f, "aes error: ")?;
	match self
	{
	    Error::Random => write!(f, "rng failure"),
	    Error::IO(io) => write!(f, "io: {}", io),
	    Error::Encrypt => write!(f, "encryption failed"),
	    Error::Decrypt => write!(f, "decryption failed"),
	    Error::Internal(ssl) => write!(f, "internal: {}", ssl),
	    Error::Length{expected: Some(expected), got: Some(got)} => write!(f, "bad length: expected {}, got {}", expected, got),
	    Error::Length{expected: Some(expected), ..} => write!(f, "bad length: expected {}", expected),
	    Error::Length{got: Some(got), ..} => write!(f, "bad length: got {}", got),
	    _ => write!(f, "unknown"),
	}
    }
}

impl From<ErrorStack> for Error
{
    fn from(ssl: ErrorStack) -> Self
    {
	Self::Internal(ssl)
    }
}

impl From<getrandom::Error> for Error
{
    #[inline] fn from(_: getrandom::Error) -> Self
    {
	Self::Random
    }
}

impl From<io::Error> for Error
{
    fn from(i: io::Error) -> Self
    {
	Self::IO(i)
    }
}
