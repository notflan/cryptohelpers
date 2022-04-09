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
use tokio::io::{
    AsyncRead,
    AsyncReadExt,
};
use consts::RSA_SIG_SIZE as SIZE;
use consts::BUFFER_SIZE;

/// Represents an RSA signature
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Signature([u8; SIZE]);
impl Default for Signature
{
    #[inline]
    fn default() -> Self
    {
	Self([0u8; SIZE])
    }
}

#[cfg(feature="serialise")] const _: () = {
    use serde::{
	Serialize,
    };

    impl Serialize for Signature
    {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
            S: serde::ser::Serializer,
	{
            serializer.serialize_bytes(&self.0[..])
	}
    }

    pub struct SignatureVisitor;

    impl<'de> serde::de::Visitor<'de> for SignatureVisitor {
	type Value = Signature;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an array of 512 bytes")
	}

	fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
	where E: serde::de::Error
	{
	    let mut output = [0u8; SIZE];
	    if v.len() == output.len() {
		unsafe {
		    std::ptr::copy_nonoverlapping(&v[0] as *const u8, &mut output[0] as *mut u8, SIZE);
		}
		Ok(Signature(output))
	    } else {
		Err(E::custom(format!("Expected {} bytes, got {}", SIZE, v.len())))
	    }
	}
	fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error> where
	    A: serde::de::SeqAccess<'de>
	{
	    let mut bytes = [0u8; SIZE];
	    let mut i=0usize;
	    while let Some(byte) = seq.next_element()?
	    {
		bytes[i] = byte;
		i+=1;
		if i==SIZE {
		    return Ok(Signature(bytes));
		}
	    }
	    use serde::de::Error;
	    Err(A::Error::custom(format!("Expected {} bytes, got {}", SIZE, i)))
	}
    }
    impl<'de> serde::Deserialize<'de> for Signature {
	fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error>
	where
            D: serde::de::Deserializer<'de>,
	{
            deserializer.deserialize_bytes(SignatureVisitor)
	}
    }

};


#[cfg(feature="serialise")]
#[cfg(test)]
mod serde_tests
{
    
    #[test]
    fn ser_de()
    {
	let pv = super::RsaPrivateKey::generate().expect("genkey");
	let mut data = [0u8; 32];
	getrandom::getrandom(&mut data[..]).expect("rng");
	
	let signature = super::sign_slice(&data[..], &pv).expect("sign");
	assert!(signature.verify_slice(&data[..], &pv).expect("verify"));

	let value = serde_cbor::to_vec(&signature).expect("ser");
	let output: super::Signature = serde_cbor::from_slice(&value[..]).expect("de");

	assert_eq!(output, signature);

	assert!(output.verify_slice(&data[..], &pv).expect("verify"));
    }
    #[test]
    fn ser_de_empty()
    {
	let signature = super::Signature::default();

	let value = serde_cbor::to_vec(&signature).expect("ser");
	let output: super::Signature = serde_cbor::from_slice(&value[..]).expect("de");

	assert_eq!(output, signature);
    }
}

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

