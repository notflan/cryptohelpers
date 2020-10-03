//! Public RSA key components
use super::*;
use offsets::*;

#[allow(unused_imports)]
use std::{
    borrow::{
	Borrow,
	Cow,
    },
    io::{
	self,
	Write,
	Read,
    },
    mem::size_of,
    marker::Unpin,
    convert::{
	TryFrom,
    },
};
use openssl::{
    bn::{
	BigNumRef,
    },
    rsa::{
	Rsa,
    },
    pkey::{
	Public,
	HasPublic,
	PKey,
    },
};
#[cfg(feature="async")]
use tokio::{
    io::{
	AsyncWrite,
	AsyncRead,
    },
    prelude::*,
};

/// Container for RSA public key components
///
/// # Notes
/// It is always assumed that the internal consistancy and state of the components binary representations is correct.
/// Incorrect internal state can cause panics on all operations.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature="serialise", derive(Serialize,Deserialize))]
pub struct RsaPublicKey
{
    data: Vec<u8>,
    offset_starts: Starts<PublicOffsetGroup>,
    offset: PublicOffsetGroup,
}

impl RsaPublicKey
{
    /// Generate a new RSA public key (kinda useless, use `RsaPrivateKey::generate()`).
    pub fn generate() -> Result<Self, Error>
    {
	Ok(Rsa::generate(RSA_KEY_BITS)?.into())
    }
    /// Create a new RSAPublicKey from components
    pub fn new(
	n: impl Borrow<BigNumRef>,
	e: impl Borrow<BigNumRef>
    ) -> Self
    {
	fn vectorise<T: Write,U: Borrow<BigNumRef>>(b: U, data: &mut T) -> usize
	{
	    let bytes = b.borrow().to_vec();
	    data.write(bytes.as_slice()).unwrap()
	}
	let mut data = Vec::new();
	let offset = offsets::PublicOffsetGroup {
	    n: vectorise(n, &mut data),
	    e: vectorise(e, &mut data),
	};

	Self {
	    offset_starts: offset.starts(),
	    offset,
	    data,
	}
    }

    /// Create a PEM string from this instance
    pub fn to_pem(&self) -> Result<String, Error>
    {
	let pkey = self.get_pkey_pub()?;
	let pem = pkey.public_key_to_pem()?;

	Ok(std::str::from_utf8(&pem[..])?.to_string())
    }

    /// Try to create a new instance from a PEM string
    pub fn from_pem(pem: impl AsRef<str>) -> Result<Self, Error>
    {
	let pem = pem.as_ref();
	let pem = pem.as_bytes();

	Ok(Rsa::public_key_from_pem(pem)?.into())
    }

    /// Validates the RSA key parameters for correctness
    pub fn check_key(&self) -> bool
    {
	self.get_rsa_pub()
	    .map(|_| true)
	    .unwrap_or(false)
    }

    /// Try to get the RSA public key from this instance
    pub fn get_rsa_pub(&self) -> Result<Rsa<Public>, Error>
    {
	Ok(Rsa::from_public_components(
	    number!(self -> n),
	    number!(self -> e)
	)?)
    }

    /// Try to construct an instance from bytes
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error>
    {
	let bytes = bytes.as_ref();

	if bytes.len() < size_of::<PublicOffsetGroup>() {
	    return Err(Error::Binary(BinaryErrorKind::Length{expected: Some(size_of::<PublicOffsetGroup>()), got: Some(bytes.len())}));
	}

	let offset = unsafe {
	    bytes::derefer_unchecked::<PublicOffsetGroup>(&bytes[..size_of::<PublicOffsetGroup>()])
		.read_unaligned()
	};
	let bytes = &bytes[size_of::<PublicOffsetGroup>()..];

	let sz = offset.body_len();
	if bytes.len() < sz {
	    return Err(Error::Binary(BinaryErrorKind::Length{expected:Some(sz), got: Some(bytes.len())}));
	}

	Ok(Self {
	    data: Vec::from(&bytes[..]),
	    offset_starts: offset.starts(),
	    offset,
	})
    }

    /// Write the binary representation of this instance to a new `Vec<u8>`
    pub fn to_bytes(&self) -> Vec<u8>
    {
	let mut output = Vec::new();
	self.write_to_sync(&mut output).unwrap();
	output
    }

    /// Return the length of the data body only (not including header).
    #[inline] pub fn len(&self) -> usize
    {
	self.data.len()
    }

    /// Write this public key as bytes to a stream
    #[cfg(feature="async")]
    pub async fn write_to<T>(&self, to: &mut T) -> io::Result<usize>
    where T: AsyncWrite + Unpin + ?Sized
    {
	to.write_all(bytes::refer(&self.offset)).await?;
	to.write_all(&self.data[..]).await?;

	Ok(size_of::<PublicOffsetGroup>() + self.data.len())
    }

    /// Write this public key as bytes to a stream
    pub fn write_to_sync<T>(&self, to: &mut T) -> io::Result<usize>
    where T: Write + ?Sized
    {
	to.write_all(bytes::refer(&self.offset))?;
	to.write_all(&self.data[..])?;

	Ok(size_of::<PublicOffsetGroup>() + self.data.len())
    }

    /// Read a public key from a stream
    #[cfg(feature="async")] 
    pub async fn read_from<T>(&self, from: &mut T) -> io::Result<Self>
    where T: AsyncRead + Unpin + ?Sized
    {
	let offset: PublicOffsetGroup = {
	    union BufHack {
		buffer: [u8; size_of::<PublicOffsetGroup>()],
		offsets: PublicOffsetGroup,
	    }
	    let mut offsets = BufHack{buffer: [0u8; size_of::<PublicOffsetGroup>()]};
	    unsafe {
		let buffer = &mut offsets.buffer;
		if buffer.len() != from.read_exact(&mut buffer[..]).await? {
		    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "couldn't read offsets"));
		}
	    }
	    unsafe {
		offsets.offsets
	    }
	};

	let mut data = vec![0u8; offset.body_len()];

	if from.read_exact(&mut data[..]).await? != data.len() {
	    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "couldn't read data body"));
	}

	Ok(Self {
	    data,
	    offset_starts: offset.starts(),
	    offset
	})
    }

    /// Read a public key from a stream
    pub fn read_from_sync<T>(&self, from: &mut T) -> io::Result<Self>
    where T: Read + ?Sized
    {
	let offset: PublicOffsetGroup = {
	    union BufHack {
		buffer: [u8; size_of::<PublicOffsetGroup>()],
		offsets: PublicOffsetGroup,
	    }
	    let mut offsets = BufHack{buffer: [0u8; size_of::<PublicOffsetGroup>()]};
	    unsafe {
		let buffer = &mut offsets.buffer;
		from.read_exact(&mut buffer[..])?;
	    }
	    unsafe {
		offsets.offsets
	    }
	};

	let mut data = vec![0u8; offset.body_len()];

	from.read_exact(&mut data[..])?;

	Ok(Self {
	    data,
	    offset_starts: offset.starts(),
	    offset
	})
    }
}

impl HasComponents for RsaPublicKey
{
    fn raw(&self) -> &[u8]
    {
	&self.data[..]
    }
}

impl From<RsaPublicKey> for Rsa<Public>
{
    #[inline] fn from(key: RsaPublicKey) -> Rsa<Public>
    {
	key.get_rsa_pub().unwrap()
    }
}

impl From<RsaPublicKey> for PKey<Public>
{
    fn from(from: RsaPublicKey) -> Self
    {
	PKey::from_rsa(from.into()).unwrap()
    }
}

impl<T> From<PKey<T>> for RsaPublicKey
where T: HasPublic
{
    fn from(from: PKey<T>) -> Self
    {
	from.rsa().unwrap().into()
    }
}

impl PublicKey for RsaPublicKey
{
    type KeyType = Public;
    type Error = Error;

    fn get_pkey_pub(&self) -> Result<Cow<'_, PKey<Self::KeyType>>, Self::Error>
    {
	Ok(Cow::Owned(PKey::from_rsa(Rsa::from_public_components(number!(self -> n), number!(self -> e))?)?))
    }
    
    fn get_rsa_pub(&self) -> Result<Option<Cow<'_, Rsa<Self::KeyType>>>, Self::Error>
    {
	Ok(Some(Cow::Owned(self.get_pkey_pub()?.rsa()?)))
    }
}


impl<T> From<Rsa<T>> for RsaPublicKey
where T: HasPublic
{
    fn from(key: Rsa<T>) -> Self
    {
	Self::new(key.n(),
		  key.e())
    }
}

impl HasPublicComponents for RsaPublicKey
{
    fn n(&self) -> &[u8]
    {
	component!(self -> n)
    }
    fn e(&self) -> &[u8]
    {
	component!(self -> e)
    }
}

impl From<RsaPublicKey> for Vec<u8>
{
    fn from(key: RsaPublicKey) -> Self
    {
	let mut vec = Self::with_capacity(key.data.len()+size_of::<PublicOffsetGroup>());
	vec.extend_from_slice(bytes::refer(&key.offset));
	vec.extend(key.data);
	vec
    }
}

impl TryFrom<Vec<u8>> for RsaPublicKey
{
    type Error = Error;

    #[inline] fn try_from(from: Vec<u8>) -> Result<Self, Self::Error>
    {
	Self::from_bytes(from)
    }
}

