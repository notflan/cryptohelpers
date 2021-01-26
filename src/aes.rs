//! Advanced Encryption Standard
use super::*;
#[allow(unused_imports)]
use std::{
    fmt,
    marker::Unpin,
    io,
};
use openssl::{
    symm::{
	Cipher,
	Crypter,
	Mode,
    },
};
#[cfg(feature="async")]
use tokio::{
    io::{
	AsyncRead,
	AsyncWrite,
    },
    prelude::*,
};
use getrandom::getrandom;

const KEYSIZE: usize = consts::AES_KEYSIZE;
const IVSIZE: usize = consts::AES_IVSIZE;
use consts::BUFFER_SIZE;
const BLOCKSIZE: usize = 16;

/// A key and IV for the AES algorithm
#[derive(Debug, PartialEq, Eq, Clone, Hash, Default, PartialOrd, Ord)]
#[cfg_attr(feature="serialise", derive(Serialize,Deserialize))]
#[repr(align(1))]
pub struct AesKey {
    key: [u8; KEYSIZE],
    iv: [u8; IVSIZE],
}

impl AesKey
{
    /// Generate a new AES key and IV.
    pub fn generate() -> Result<Self, Error>
    {
	let mut this = Self::default();

	getrandom(&mut this.key[..])?;
	getrandom(&mut this.iv[..])?;

	Ok(this)
    }
    /// Generate a new random AES key and IV.
    ///
    /// # Deprecated
    /// Use `AesKey::generate()` instead.
    #[deprecated] #[inline]  pub fn random() -> Result<Self, Error>
    {
	Self::generate()
    }

    /// Create a new instance from a key and IV
    pub const fn new(key: [u8; KEYSIZE], iv: [u8; IVSIZE]) -> Self
    {
	Self{key,iv}
    }

    /// Consume into the key and IV parts
    pub const fn into_parts(self) -> ([u8; KEYSIZE], [u8; IVSIZE])
    {
        (self.key, self.iv)
    }

    /// Consume this instance into the full byte buffer
    pub fn into_bytes(self) -> [u8; KEYSIZE+IVSIZE]
    {
        unsafe { std::mem::transmute(self) }
    }

    /// Consume a full byte buffer into an AES key
    pub fn from_bytes(from: [u8; KEYSIZE+IVSIZE]) -> Self
    {	
        unsafe { std::mem::transmute(from) }
    }

    /// Create a zero inisialised key
    #[inline] pub const fn empty() -> Self
    {
	Self { iv: [0; IVSIZE], key: [0; KEYSIZE]}
    }

    /// Create a new instance from slices
    pub fn from_slice(key: impl AsRef<[u8]>, iv: impl AsRef<[u8]>) -> Result<Self,Error>
    {
	let mut this = Self::default();
	if bytes::copy_slice(&mut this.key[..], key.as_ref()) != this.key.len() {
	    Err(Error::Length{expected: Some(this.key.len()), got: None})
	} else {
	    Ok(())
	}?;

	if bytes::copy_slice(&mut this.iv[..], iv.as_ref()) != this.iv.len() {
	    Err(Error::Length{expected: Some(this.iv.len()), got: None})
	} else {
	    Ok(this)
	}
    }

    /// The key part of this `AesKey` instance
    pub fn k(&self) -> &[u8]
    {
	&self.key[..]
    }

    /// The IV part of this `AesKey` instance
    pub fn i(&self) -> &[u8]
    {
	&self.iv[..]
    }

    /// A mutable reference of the key part of this `AesKey` instance
    pub fn k_mut(&mut self) -> &mut [u8]
    {
	&mut self.key[..]
    }
    
    /// A mutable reference of the IV part of this `AesKey` instance
    pub fn i_mut(&mut self) -> &mut [u8]
    {
	&mut self.iv[..]
    }
}

impl AsRef<[u8]> for AesKey
{
    fn as_ref(&self) -> &[u8]
    {
	bytes::refer(self)
    }
}

impl AsMut<[u8]> for AesKey
{
    fn as_mut(&mut self) -> &mut [u8]
    {
	bytes::refer_mut(self)
    }
}

impl fmt::Display for AesKey
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	write!(f, "AesKey (Key: ")?;
	for byte in self.key.iter() {
	    write!(f, "{:0x}", byte)?;
	}
	write!(f, ", IV: ")?;
	for byte in self.iv.iter() {
	    write!(f, "{:0x}", byte)?;
	}
	write!(f, ")")
    }
}

/// Encrypt a stream into another using a key
#[cfg(feature="async")] 
pub async fn encrypt_stream<F,T>(key: &AesKey, from: &mut F, to: &mut T) -> Result<usize, Error>
where F: AsyncRead + Unpin + ?Sized,
      T: AsyncWrite + Unpin + ?Sized
{
    let mut read;
    let mut done=0;

    let mut crypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Encrypt, &key.key[..], Some(&key.iv[..]))?;
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut crypt_buffer = [0u8; BUFFER_SIZE + BLOCKSIZE];
    while {read = from.read(&mut buffer[..]).await?; read!=0} {
	let bytes_encrypted = crypter.update(&buffer[..read], &mut crypt_buffer)?;
	to.write_all(&crypt_buffer[..bytes_encrypted]).await?;
	done += bytes_encrypted;
    }

    let bytes_encrypted = crypter.finalize(&mut crypt_buffer)?;
    to.write_all(&crypt_buffer[..bytes_encrypted]).await?;

    Ok(done + bytes_encrypted)
}

/// Encrypt a stream into another using a key
pub async fn encrypt_stream_sync<F,T>(key: &AesKey, from: &mut F, to: &mut T) -> Result<usize, Error>
where F: io::Read + ?Sized,
      T: io::Write + ?Sized
{
    let mut read;
    let mut done=0;

    let mut crypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Encrypt, &key.key[..], Some(&key.iv[..]))?;
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut crypt_buffer = [0u8; BUFFER_SIZE + BLOCKSIZE];
    while {read = from.read(&mut buffer[..])?; read!=0} {
	let bytes_encrypted = crypter.update(&buffer[..read], &mut crypt_buffer)?;
	to.write_all(&crypt_buffer[..bytes_encrypted])?;
	done += bytes_encrypted;
    }

    let bytes_encrypted = crypter.finalize(&mut crypt_buffer)?;
    to.write_all(&crypt_buffer[..bytes_encrypted])?;

    Ok(done + bytes_encrypted)
}

/// Decrypt a stream into another using a key
#[cfg(feature="async")] 
pub async fn decrypt_stream<F,T>(key: &AesKey, from: &mut F, to: &mut T) -> Result<usize, Error>
where F: AsyncRead + Unpin + ?Sized,
      T: AsyncWrite + Unpin + ?Sized
{
    let mut read;
    let mut done=0;

    let mut crypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Decrypt, &key.key[..], Some(&key.iv[..]))?;
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut crypt_buffer = [0u8; BUFFER_SIZE + BLOCKSIZE];
    while {read = from.read(&mut buffer[..]).await?; read!=0} {
	let bytes_encrypted = crypter.update(&buffer[..read], &mut crypt_buffer)?;
	to.write_all(&crypt_buffer[..bytes_encrypted]).await?;
	done += bytes_encrypted;
    }

    let bytes_encrypted = crypter.finalize(&mut crypt_buffer)?;
    to.write_all(&crypt_buffer[..bytes_encrypted]).await?;

    Ok(done + bytes_encrypted)
}

/// Decrypt a stream into another using a key
pub async fn decrypt_stream_sync<F,T>(key: &AesKey, from: &mut F, to: &mut T) -> Result<usize, Error>
where F: io::Read + ?Sized,
      T: io::Write + ?Sized
{
    let mut read;
    let mut done=0;

    let mut crypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Decrypt, &key.key[..], Some(&key.iv[..]))?;
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut crypt_buffer = [0u8; BUFFER_SIZE + BLOCKSIZE];
    while {read = from.read(&mut buffer[..])?; read!=0} {
	let bytes_encrypted = crypter.update(&buffer[..read], &mut crypt_buffer)?;
	to.write_all(&crypt_buffer[..bytes_encrypted])?;
	done += bytes_encrypted;
    }

    let bytes_encrypted = crypter.finalize(&mut crypt_buffer)?;
    to.write_all(&crypt_buffer[..bytes_encrypted])?;

    Ok(done + bytes_encrypted)
}

pub use crate::error::aes::Error;

#[cfg(test)]
mod tests
{
    #[test]
    fn transmute_safe()
    {
	use std::mem::{size_of, align_of};

	assert_eq!(size_of::<super::AesKey>(), size_of::<[u8; super::KEYSIZE + super::IVSIZE]>());
	assert_eq!(align_of::<super::AesKey>(), align_of::<[u8; super::KEYSIZE + super::IVSIZE]>());
	let key = super::AesKey::generate().unwrap();

	let bytes = Vec::from(key.as_ref());
	let tbytes = key.clone().into_bytes();

	let nkey = super::AesKey::from_bytes(tbytes);

	assert_eq!(nkey, key);
	assert_eq!(&bytes[..], &tbytes[..]);
	assert_eq!(key.as_ref(), &tbytes[..]);
    }
}
