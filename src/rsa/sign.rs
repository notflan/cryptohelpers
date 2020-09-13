//! RSA signing
use super::*;
#[allow(unused_imports)]
use std::{
    cmp::{PartialEq,Eq,},
    hash::{Hash,Hasher,},
    fmt::{
	self,
	Display,
	Debug,
    },
    marker::Unpin,
    io::{
	Read,
    },
};
use openssl::{
    hash::{
	MessageDigest,
    },
    sign::{
	Signer,
	Verifier,
    },
    pkey::{
	HasPrivate,
    },
};
#[cfg(feature="async")] 
use tokio::{
    io::{
	AsyncRead,
    },
    prelude::*,
};
use consts::RSA_SIG_SIZE as SIZE;
use consts::BUFFER_SIZE;

/// Represents an RSA signature
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct Signature([u8; SIZE]);

impl Signature
{
    /// Create from an exact array
    pub const fn from_exact(from: [u8; SIZE]) -> Self
    {
	Self(from)
    }

    /// Create from a silce.
    ///
    /// # Panics
    /// If `from` is not at least `RSA_SIG_SIZE` bytes long
    pub fn from_slice(from: impl AsRef<[u8]>) -> Self
    {
	let mut output = [0u8; SIZE];
	assert_eq!(bytes::copy_slice(&mut output[..], from.as_ref()), SIZE);
	Self(output)
    }
    
    /// Verify this signature for a slice of data
    pub fn verify_slice<T,K>(&self, slice: T, key: &K) -> Result<bool, Error>
    where K: PublicKey + ?Sized,
	  T: AsRef<[u8]>
    {
	let pkey = key.get_pkey_pub().map_err(|_| Error::Key)?;

	let mut veri = Verifier::new(MessageDigest::sha256(), &pkey)?;
	veri.update(slice.as_ref())?;
	
	Ok(veri.verify(&self.0[..])?)
    }

    /// Verify this signature for a stream of data. Returns the success and number of bytes read.
    #[cfg(feature="async")] 
    pub async fn verify<T,K>(&self, from: &mut T, key: &K) -> Result<(bool, usize), Error>
    where T: AsyncRead + Unpin + ?Sized,
	  K: PublicKey + ?Sized
    {
	let pkey = key.get_pkey_pub().map_err(|_| Error::Key)?;

	let mut veri = Verifier::new(MessageDigest::sha256(), &pkey)?;
	let done = {
	    let mut read;
	    let mut done = 0;
	    let mut buffer = [0u8; BUFFER_SIZE];
	    while {read = from.read(&mut buffer[..]).await?; read!=0} {
		veri.update(&buffer[..read])?;
		done+=read;
	    }
	    done
	};

	Ok((veri.verify(&self.0[..])?, done))
    }
    /// Verify this signature for a stream of data. Returns the success and number of bytes read.
    pub fn verify_sync<T,K>(&self, from: &mut T, key: &K) -> Result<(bool, usize), Error>
    where T: Read + ?Sized,
	  K: PublicKey + ?Sized
    {
	let pkey = key.get_pkey_pub().map_err(|_| Error::Key)?;

	let mut veri = Verifier::new(MessageDigest::sha256(), &pkey)?;
	let done = {
	    let mut read;
	    let mut done = 0;
	    let mut buffer = [0u8; BUFFER_SIZE];
	    while {read = from.read(&mut buffer[..])?; read!=0} {
		veri.update(&buffer[..read])?;
		done+=read;
	    }
	    done
	};

	Ok((veri.verify(&self.0[..])?, done))
    }
}

/// Compute the signature for a slice of bytes
pub fn sign_slice<T,K>(data: T, key: &K) -> Result<Signature, Error>
where T: AsRef<[u8]>,
      K: PrivateKey + ?Sized,
<K as PublicKey>::KeyType: HasPrivate //ugh
{
    let pkey = key.get_pkey_priv().map_err(|_| Error::Key)?;

    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(data.as_ref())?;

    let mut output = [0u8; SIZE];
    assert_eq!(signer.sign(&mut output[..])?, SIZE);
    
    Ok(Signature(output))
}

/// Compute the signature for this stream, returning it and the number of bytes read
#[cfg(feature="async")] 
pub async fn sign<T,K>(data: &mut T, key: &K) -> Result<(Signature, usize), Error>
where T: AsyncRead + Unpin + ?Sized,
      K: PrivateKey + ?Sized,
<K as PublicKey>::KeyType: HasPrivate //ugh
{
    
    let pkey = key.get_pkey_priv().map_err(|_| Error::Key)?;

    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    let done = {
	let mut read;
	let mut done=0;
	let mut buffer = [0u8; SIZE];

	while {read = data.read(&mut buffer[..]).await?; read!=0} {
	    signer.update(&buffer[..read])?;
	    done+=read;
	}
	done
    };
    
    let mut output = [0u8; SIZE];
    assert_eq!(signer.sign(&mut output[..])?, SIZE);
    
    Ok((Signature(output), done))
}
/// Compute the signature for this stream, returning it and the number of bytes read
pub fn sign_sync<T,K>(data: &mut T, key: &K) -> Result<(Signature, usize), Error>
where T: Read + ?Sized,
      K: PrivateKey + ?Sized,
<K as PublicKey>::KeyType: HasPrivate //ugh
{
    
    let pkey = key.get_pkey_priv().map_err(|_| Error::Key)?;

    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    let done = {
	let mut read;
	let mut done=0;
	let mut buffer = [0u8; SIZE];

	while {read = data.read(&mut buffer[..])?; read!=0} {
	    signer.update(&buffer[..read])?;
	    done+=read;
	}
	done
    };
    
    let mut output = [0u8; SIZE];
    assert_eq!(signer.sign(&mut output[..])?, SIZE);
    
    Ok((Signature(output), done))
}

// Boilerplate

impl AsRef<[u8]> for Signature
{
    fn as_ref(&self) -> &[u8]
    {
	&self.0[..]
    }
}

impl AsMut<[u8]> for Signature
{
    fn as_mut(&mut self) -> &mut [u8]
    {
	&mut self.0[..]
    }
}

impl Default for Signature
{
    #[inline]
    fn default() -> Self
    {
	Self([0u8; SIZE])
    }
}

impl Eq for Signature{}
impl PartialEq for Signature
{
    #[inline] fn eq(&self, other: &Self) -> bool
    {
	&self.0[..] == &other.0[..]
    }
}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
	self.0[..].hash(state)
    }
}

impl Debug for Signature
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	write!(f, "Signature ({:?})", &self.0[..])
    }
}

impl Display for Signature
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	write!(f, "Signature (")?;
	for byte in self.0.iter()
	{
	    write!(f, "{:0x}", byte)?;
	}
	write!(f,")")
    }
}

