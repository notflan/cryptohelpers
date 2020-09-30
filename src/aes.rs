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
#[derive(Debug, PartialEq, Eq, Clone, Hash, Default)]
#[cfg_attr(feature="serialise", derive(Serialize,Deserialize))]
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
