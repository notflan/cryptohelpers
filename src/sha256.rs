//! Deals with SHA256 hashing
use super::*;
#[allow(unused_imports)]
use std::{
    fmt,
    marker::Unpin,
    io,
};
use sha2::{
    Digest, Sha256,
};
#[cfg(feature="async")] 
use tokio::{
    io::AsyncRead,
    prelude::*,
};

const SIZE: usize = consts::SHA256_SIZE;

/// Represents a SHA256 hash
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
#[repr(C, packed)]
pub struct Sha256Hash
{
    hash: [u8; SIZE],
}

impl Sha256Hash
{
    /// Return an empty SHA256 hash container
    pub const fn empty() -> Self
    {
	Self { hash: [0u8; SIZE] }
    }

    /// Reads the rest of the stream, and computes SHA256 hash into the current instance. Returning the number of bytes read.
    #[cfg(feature="async")] 
    pub async fn compute_into<T>(&mut self, from: &mut T) -> io::Result<usize>
    where T: AsyncRead + Unpin + ?Sized
    {
	let mut buffer = [0u8; super::BUFFER_SIZE];
	let mut hasher = Sha256::new();
	let mut read:usize;
	let mut done=0;
	while (read = from.read(&mut buffer[..]).await?, read!=0).1 {
	    hasher.update(&buffer[..read]);
	    done+=read;
	}

	bytes::copy_slice(&mut self.hash[..], &hasher.finalize());
	Ok(done)
    }
    
    /// Reads the rest of the stream, and computes SHA256 hash into the current instance. Returning the number of bytes read.
    pub fn compute_into_sync<T>(&mut self, from: &mut T) -> io::Result<usize>
    where T: io::Read + Unpin + ?Sized
    {
	let mut buffer = [0u8; super::BUFFER_SIZE];
	let mut hasher = Sha256::new();
	let mut read:usize;
	let mut done=0;
	while (read = from.read(&mut buffer[..])?, read!=0).1 {
	    hasher.update(&buffer[..read]);
	    done+=read;
	}
	
	bytes::copy_slice(&mut self.hash[..], &hasher.finalize());
	Ok(done)
    }
}

impl fmt::Display for Sha256Hash
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	write!(f, "SHA256 (")?;
	for x in self.hash.iter() {
	    write!(f, "{:x}", x)?;
	}
	write!(f, ")")
    }
}

impl From<Sha256> for Sha256Hash
{
    fn from(from: Sha256) -> Self
    {
	let mut hash = [0; SIZE];
	bytes::copy_slice(&mut hash, &from.finalize());
	Self{hash}
    }
}

/// Compute the SHA256 hash of the rest of this stream
#[cfg(feature="async")] 
pub async fn compute<T>(from: &mut T) -> io::Result<Sha256Hash>
where T: AsyncRead + Unpin + ?Sized
{
    let mut buffer = [0u8; super::BUFFER_SIZE];
    let mut hasher = Sha256::new();
    let mut read:usize;
    while (read = from.read(&mut buffer[..]).await?, read!=0).1 {
	hasher.update(&buffer[..read]);
    }

    let mut hash = [0u8; SIZE];
    bytes::copy_slice(&mut hash[..], &hasher.finalize());
    Ok(Sha256Hash{hash})
}


/// Compute SHA256 hash from a slice.
pub fn compute_slice<T>(from: T) -> Sha256Hash
where T: AsRef<[u8]>
{
    let from = from.as_ref();
    let mut hasher = Sha256::new();
    hasher.update(from);

    let mut hash = [0u8; SIZE];
    bytes::copy_slice(&mut hash, &hasher.finalize());
    Sha256Hash{hash}
}


/// Compute the SHA256 hash of the rest of this stream
pub fn compute_sync<T>(from: &mut T) -> io::Result<Sha256Hash>
where T: io::Read + Unpin + ?Sized
{
    let mut buffer = [0u8; super::BUFFER_SIZE];
    let mut hasher = Sha256::new();
    let mut read:usize;
    while (read = from.read(&mut buffer[..])?, read!=0).1 {
	hasher.update(&buffer[..read]);
    }

    let mut hash = [0u8; SIZE];
    bytes::copy_slice(&mut hash[..], &hasher.finalize());
    Ok(Sha256Hash{hash})
}

impl AsRef<[u8]> for Sha256Hash
{
    #[inline] fn as_ref(&self) -> &[u8]
    {
	&self.hash[..]
    }
}

impl AsMut<[u8]> for Sha256Hash
{
    fn as_mut(&mut self) -> &mut [u8]
    {
	&mut self.hash[..]
    }
}
