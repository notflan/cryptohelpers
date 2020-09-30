//! Password related functions
use super::*;
use std::{
    fmt,
};
use pbkdf2::{
    pbkdf2,
};
use sha2::{
    Sha256,
};
use hex_literal::hex;
use hmac::Hmac;
use getrandom::getrandom;

pub const SALTSIZE: usize = consts::PASSWORD_SALTSIZE;
pub const KEYSIZE: usize = consts::PASSWORD_KEYSIZE;
pub const ROUNDS: u32 = consts::PASSWORD_ROUNDS;

/// Represents a password hash
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
#[cfg_attr(feature="serialise", derive(Serialize,Deserialize))]
pub struct Password {
    derived: [u8; KEYSIZE],
}

/// Represents a salt to be used for password operations
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
#[cfg_attr(feature="serialise", derive(Serialize,Deserialize))]
pub struct Salt([u8; SALTSIZE]);

impl Default for Salt
{
    #[inline]
    fn default() -> Self
    {
	Self::embedded()
    }
}

/// The salt value used for `Salt::embedded()`.
pub const STATIC_SALT: [u8; SALTSIZE] = hex!("d0a2404173bac722b29282652f2c457b573261e3c8701b908bb0bd3ada3d7f2d");

impl Salt
{
    /// The default embedded static salt
    pub const fn embedded() -> Self
    {
	Self(STATIC_SALT)
    }

    /// Generate a random salt
    pub fn random() -> Result<Self, Error>
    {
	let mut output = [0u8; SALTSIZE];
	match getrandom(&mut output[..]) {
	    Ok(_) => Ok(Self(output)),
	    Err(_) => Err(Error::Random),
	}
    }

    /// Create a specific salt
    #[inline] pub const fn specific(from: [u8; SALTSIZE]) -> Self
    {
	Self(from)
    }

    /// Create a specific salt from a slice
    pub fn slice<T>(from: T) -> Result<Self, Error>
	where T: AsRef<[u8]>
    {
	let mut this = Self::none();
	if bytes::copy_slice(&mut this.0[..], from.as_ref()) != this.0.len() {
	    Err(Error::Length{expected: Some(this.0.len()), got: None})
	} else {
	    Ok(this)
	}
    }

    /// An empty salt
    #[inline] pub const fn none() -> Self
    {
	Self([0u8; SALTSIZE])
    }

}

impl From<[u8; SALTSIZE]> for Salt
{
    #[inline] fn from(from: [u8; SALTSIZE]) -> Self
    {
	Self::specific(from)
    }
}

impl From<Salt> for [u8; SALTSIZE]
{
    #[inline] fn from(from: Salt) -> Self
    {
	from.0
    }
}

impl AsRef<[u8]> for Salt
{
    fn as_ref(&self) -> &[u8]
    {
	&self.0[..]
    }
}

impl AsMut<[u8]> for Salt
{
    fn as_mut(&mut self) -> &mut [u8]
    {
	&mut self.0[..]
    }
}


impl Password
{
    /// Create from a specific hash
    #[inline] pub const fn from_bytes(derived: [u8; KEYSIZE]) -> Self
    {
	Self { derived }
    }

    /// Consume into the hash bytes
    #[inline] 
    pub const fn into_bytes(self) -> [u8; KEYSIZE]
    {
	self.derived
    }
    
    /// Create an empty password hash container
    #[inline(always)] pub const fn empty() -> Self
    {
	Self{derived: [0u8; KEYSIZE]}
    }
    
    /// Create an AES key from this password hash
    #[cfg(feature="aes")] 
    #[inline] pub fn create_aes(&self) -> aes::AesKey
    {
	aes::AesKey::from_slice(&self.derived[..consts::AES_KEYSIZE], &self.derived[consts::AES_KEYSIZE..]).unwrap()
    }
    /// Validate this password.
    pub fn validate(&self, string: impl AsRef<str>, salt: &Salt) -> bool
    {
	&Self::derive(string, salt) == self
    }

    /// Derive a password hash from string and salt
    pub fn derive(string: impl AsRef<str>, salt: &Salt) -> Password
    {
	let string = string.as_ref();
	let mut derived = [0u8; KEYSIZE];
	pbkdf2::<Hmac<Sha256>>(string.as_bytes(), &salt.0[..], ROUNDS, &mut derived[..]);

	Self{derived}
    }
}

impl AsRef<[u8]> for Password
{
    #[inline] fn as_ref(&self) -> &[u8]
    {
	&self.derived[..]
    }
}

impl AsMut<[u8]> for Password
{
    #[inline] fn as_mut(&mut self) -> &mut [u8]
    {
	&mut self.derived[..]
    }
}

impl fmt::Display for Password
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	for x in self.derived.iter()
	{
	    write!(f, "{:x}", x)?;
	}
	Ok(())
    }
}

#[cfg(feature="aes")]
impl From<Password> for aes::AesKey
{
    #[inline] fn from(from: Password) -> Self
    {
	unsafe {
	    std::mem::transmute(from)
	}
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    #[test]
    #[cfg(feature="aes")] 
    fn transmute_safe()
    {
	assert_eq!(std::mem::size_of::<Password>(), std::mem::size_of::<aes::AesKey>());
	assert_eq!(std::mem::align_of::<Password>(), std::mem::align_of::<aes::AesKey>());

	let passwd = Password::derive("hello world", &Default::default());
	let naes = passwd.create_aes();
	let aes: aes::AesKey = passwd.into();

	assert_eq!(aes, naes);
    }
}


pub use crate::error::password::Error;
