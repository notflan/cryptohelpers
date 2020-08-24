//! Password related error
use super::*;

/// Represents an error regarding password related operations
#[derive(Debug)]
pub enum Error
{
    Random,
    Unknown,
    Length{expected: Option<usize>, got: Option<usize>},
}
impl error::Error for Error{}

impl fmt::Display for Error
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	match self {
	    Error::Random => write!(f, "rng failure"),
	    Error::Length{expected: Some(expected), got: Some(got)} => write!(f, "bad length: expected {}, got {}", expected, got),
	    Error::Length{expected: Some(expected), ..} => write!(f, "bad length: expected {}", expected),
	    Error::Length{got: Some(got), ..} => write!(f, "bad length: got {}", got),
	    Error::Length{..} => write!(f, "bad length"),
	    _ => write!(f, "unknown"),	    
	}
    }
}
