//! RSA errors
use std::{
    fmt,
    io,
    error,
    num::TryFromIntError,
};
use openssl::{
    error::ErrorStack,
};

/// Binary error reason
#[derive(Debug)]
pub enum BinaryErrorKind {
    Unknown,
    Length{expected: Option<usize>, got: Option<usize>},
    Corruption,
}

/// Represents an error for RSA operations
#[derive(Debug)]
pub enum Error {
    Encrypt,
    Decrypt,
    
    Integer,
    Key,
    Password,
    PEM,
    Binary(BinaryErrorKind),
    Utf8,
    OpenSSLInternal(ErrorStack),
    IO(io::Error),
    Unknown,
}

impl error::Error for Error
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)>
    {
	Some(match &self {
	    Self::IO(io) => io,
	    Self::OpenSSLInternal(ssl) => ssl,
	    _ => return None,
	})
    }
}
impl std::fmt::Display for Error
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	match self {
	    Self::Encrypt => write!(f, "encryption failed"),
	    Self::Decrypt => write!(f, "decryption failed"),
	    Self::Integer => write!(f, "integer operation exceeded bounds (overflow/underflow)"),
	    Self::Key => write!(f, "invalid key"),
	    Self::Password => write!(f, "a password is needed but none was provided"),
	    Self::PEM => write!(f, "invalid PEM string"),
	    Self::Binary(BinaryErrorKind::Length{expected: Some(expected), got: Some(got)}) => write!(f, "invalid binary representation: bad length (expected {} got {})", expected, got),
	    Self::Binary(BinaryErrorKind::Length{expected: Some(expected), ..}) => write!(f, "invalid binary representation: bad length (expected {})", expected),
	    Self::Binary(BinaryErrorKind::Length{got: Some(got), ..}) => write!(f, "invalid binary representation: bad length (got {})", got),
	    Self::Binary(BinaryErrorKind::Length{..}) => write!(f, "invalid binary representation: bad length"),
	    Self::Binary(BinaryErrorKind::Corruption) => write!(f, "invalid binary representation: corrupted data"),
	    Self::Binary(_) => write!(f, "invalid binary representation"),
	    Self::Utf8 => write!(f, "text contained invalid utf8"),
	    Self::IO(io) => write!(f, "i/o error: {}", io),
	    Self::OpenSSLInternal(ssl) => write!(f, "openssl error: {}", ssl),
	    _ => write!(f, "unknown error"),
	}
    }
}

impl From<ErrorStack> for Error
{
    #[inline] fn from(from: ErrorStack) -> Self
    {
	Self::OpenSSLInternal(from)
    }
}

impl From<io::Error> for Error
{
    fn from(from: io::Error) -> Self
    {
	Self::IO(from)
    }
}

impl From<std::str::Utf8Error> for Error
{
    fn from(_: std::str::Utf8Error) -> Self
    {
	Self::Utf8
    }
}

impl From<TryFromIntError> for Error
{
    fn from(_: TryFromIntError) -> Self
    {
	Self::Integer
    }
}
