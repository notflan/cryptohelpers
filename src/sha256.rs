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

pub const SIZE: usize = consts::SHA256_SIZE;

/// Represents a SHA256 hash
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
#[cfg_attr(feature="serialise", derive(Serialize,Deserialize))]
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

    /// Create a SHA256 instance from these bytes
    #[inline] pub const fn from_bytes(hash: [u8; SIZE]) -> Self
    {
        Self { hash }   
    }

    /// Consume this instance into bytes
    #[inline] pub const fn into_bytes(self) -> [u8; SIZE]
    {
        self.hash
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


/// Compute SHA256 hash from an iterator of slices.
pub fn compute_slice_iter<T, I>(from: I) -> Sha256Hash
where T: AsRef<[u8]>,
      I: IntoIterator<Item=T>
{
    let mut hasher = Sha256::new();
    for from in from.into_iter()
    {
	hasher.update(from.as_ref());
    }

    let mut hash = [0u8; SIZE];
    bytes::copy_slice(&mut hash, &hasher.finalize());
    Sha256Hash{hash}
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

/// Compute a SHA256 hash from a stream of slices
#[cfg(feature="async")]
pub async fn compute_slices_stream<T, I>(mut from: I) -> Sha256Hash
where I: futures::stream::Stream<Item=T> + std::marker::Unpin,
      T: AsRef<[u8]>
{
    use futures::stream::StreamExt;
    let mut hasher = Sha256::new();
    while let Some(from) = from.next().await {
	hasher.update(from.as_ref());
    }

    let mut hash = [0u8; SIZE];
    bytes::copy_slice(&mut hash, &hasher.finalize());
    Sha256Hash{hash}
}

/// Compute a SHA256 hash from a number of slices
pub fn compute_slices<T, I>(from: I) -> Sha256Hash
where I: IntoIterator<Item=T>,
      T: AsRef<[u8]>
{
    let mut hasher = Sha256::new();
    for from in from.into_iter() {
	hasher.update(from.as_ref());
    }

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

impl From<[u8; SIZE]> for Sha256Hash
{
    #[inline] fn from(hash: [u8; SIZE]) -> Self
    {
	Self { hash }
    }
}

impl From<Sha256Hash> for [u8; SIZE]
{
    #[inline] fn from(from: Sha256Hash) -> Self
    {
	from.hash
    }
}

#[cfg(feature="password")] 
impl From<Sha256Hash> for password::Password
{
    #[inline] fn from(from: Sha256Hash) -> Self
    {
	Self::from_bytes(from.hash)
    }
}
