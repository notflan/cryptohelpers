//! Private key components
use super::*;
use offsets::*;
use crate::password::{
    Password,
};
#[allow(unused_imports)]
use std::{
    borrow::{
	Borrow,
	Cow,
    },
    mem::{
	size_of,
    },
    marker::Unpin,
    io::{
	self,
	Write,
	Read,
    },
    convert::{
	TryFrom,
    },
};
use openssl::{
    bn::BigNumRef,
    rsa::{
	Rsa,
    },
    pkey::{
	Public,
	Private,
	HasPrivate,
	PKey,
    },
    symm::Cipher,
};
#[cfg(feature="async")] 
use tokio::{
    io::{
	AsyncWrite,
	AsyncRead,
    },
    prelude::*,
};

/// Container for the private & public parts of an RSA key
///
/// # Notes
/// It is always assumed that the internal consistancy and state of the components binary representations is correct.
/// Incorrect internal state can cause panics on all operations.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RsaPrivateKey
{
    data: Vec<u8>,
    offset_starts: Starts<PrivateOffsetGroup>,
    offset: PrivateOffsetGroup,
}

impl RsaPrivateKey
{
    /// Create a new private key from its components
    pub fn new(
	n: impl Borrow<BigNumRef>,
	e: impl Borrow<BigNumRef>,
	d: impl Borrow<BigNumRef>,
	p: impl Borrow<BigNumRef>,
	q: impl Borrow<BigNumRef>,
	dmp1: impl Borrow<BigNumRef>,
	dmq1: impl Borrow<BigNumRef>,
	iqmp: impl Borrow<BigNumRef>
    ) -> Self
    {
	fn vectorise(b: impl Borrow<BigNumRef>, data: &mut Vec<u8>) -> usize
	{
	    let bytes = b.borrow().to_vec();
	    let len = bytes.len();
	    data.extend(bytes);
	    len
	}

	let mut data = Vec::new();
	let offset = PrivateOffsetGroup {
	    n: vectorise(n, &mut data),
	    e: vectorise(e, &mut data),
	    d: vectorise(d, &mut data),
	    p: vectorise(p, &mut data),
	    q: vectorise(q, &mut data),
	    dmp1: vectorise(dmp1, &mut data),
	    dmq1: vectorise(dmq1, &mut data),
	    iqmp: vectorise(iqmp, &mut data),
	};

	Self {
	    offset_starts: offset.starts(),
	    offset,
	    data,
	}
    }
}

impl RsaPrivateKey
{
    /// Try to get the RSA private key from this instance
    pub fn get_rsa_priv(&self) -> Result<Rsa<Private>, Error>
    {
	Ok(Rsa::from_private_components(
	    number!(self -> n),
	    number!(self -> e),
	    number!(self -> d),
	    number!(self -> p),
	    number!(self -> q),
	    number!(self -> dmp1),
	    number!(self -> dmq1),
	    number!(self -> iqmp)
	)?)
    }
    
    /// Try to get the RSA public key from this instance of private key
    pub fn get_rsa_pub(&self) -> Result<Rsa<Public>, Error>
    {
	Ok(Rsa::from_public_components(
	    number!(self -> n),
	    number!(self -> e)
	)?)
    }


    /// Get the public parts of this private key
    pub fn get_public_parts(&self) -> RsaPublicKey
    {
	RsaPublicKey::new(
	    self.num_n(),
	    self.num_e()
	)
    }

    /// Create a PEM string from this instance
    pub fn to_pem(&self, pw: Option<&Password>) -> Result<String, Error>
    {
	let rsa = self.get_rsa_priv()?;
	Ok(std::str::from_utf8(&match pw {
	    Some(password) => {
		rsa.private_key_to_pem_passphrase(Cipher::aes_128_cbc(), password.as_ref())?
	    },
	    None => {
		rsa.private_key_to_pem()?
	    },
	})?.to_owned())
    }

    /// Try to create an instance from PEM, requesting password if needed
    pub fn from_pem<F>(&self, pem: impl AsRef<str>, pw: F) -> Result<Self, Error>
    where F: FnOnce() -> Option<Password>
    {
	let pem = pem.as_ref().as_bytes();
	Ok(Rsa::private_key_from_pem_callback(pem, |buf| {
	    if let Some(pw) = pw() {
		Ok(bytes::copy_slice(buf, pw.as_ref()))
	    } else {
		Ok(0)
	    }
	})?.into())
    }

    /// Validates the RSA key parameters for correctness
    pub fn check_key(&self) -> bool
    {
	self.get_rsa_priv()
	    .map(|rsa| rsa.check_key().unwrap_or(false))
	    .unwrap_or(false)
    }

    /// Try to construct an instance from bytes
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error>
    {
	const OFF_SIZE: usize = size_of::<PrivateOffsetGroup>();
	let bytes = bytes.as_ref();

	if bytes.len() < OFF_SIZE {
	    return Err(Error::Binary(BinaryErrorKind::Length{expected: Some(OFF_SIZE), got: Some(bytes.len())}));
	}

	let offset: &PrivateOffsetGroup = bytes::derefer(&bytes[..OFF_SIZE]);
	let bytes = &bytes[OFF_SIZE..];
	let sz = offset.body_len();

	if bytes.len() < sz {
	    return Err(Error::Binary(BinaryErrorKind::Length{expected: Some(sz), got: Some(bytes.len())}));
	}

	Ok(Self{
	    data: Vec::from(&bytes[..]),
	    offset_starts: offset.starts(),
	    offset: *offset,
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
    
    /// Write this private key as bytes to a stream
    #[cfg(feature="async")]
    pub async fn write_to<T>(&self, to: &mut T) -> io::Result<usize>
    where T: AsyncWrite + Unpin + ?Sized
    {
	to.write_all(bytes::refer(&self.offset)).await?;
	to.write_all(&self.data[..]).await?;

	Ok(size_of::<PrivateOffsetGroup>() + self.data.len())
    }
    /// Write this private key as bytes to a stream
    pub fn write_to_sync<T>(&self, to: &mut T) -> io::Result<usize>
    where T: Write + ?Sized
    {
	to.write_all(bytes::refer(&self.offset))?;
	to.write_all(&self.data[..])?;

	Ok(size_of::<PrivateOffsetGroup>() + self.data.len())
    }
    
    /// Read a private key from a stream
    #[cfg(feature="async")] 
    pub async fn read_from<T>(&self, from: &mut T) -> io::Result<Self>
    where T: AsyncRead + Unpin + ?Sized
    {
	const OFF_SIZE: usize = size_of::<PrivateOffsetGroup>();
	
	let offset: PrivateOffsetGroup = {
	    let mut buffer = [0u8; OFF_SIZE];

	    if buffer.len() != from.read_exact(&mut buffer[..]).await? {
		return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "couldn't read offsets"));
	    } else {
		*bytes::derefer(&buffer[..])
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

    /// Read a private key from a stream
    pub fn read_from_sync<T>(&self, from: &mut T) -> io::Result<Self>
    where T: Read + ?Sized
    {
	let offset: PrivateOffsetGroup = {
	    let mut buffer = [0u8; size_of::<PrivateOffsetGroup>()];

	    from.read_exact(&mut buffer[..])?;
	    *bytes::derefer(&buffer[..])
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

impl HasComponents for RsaPrivateKey
{
    fn raw(&self) -> &[u8]
    {
	return &self.data[..]
    }
}

impl HasPublicComponents for RsaPrivateKey
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
impl HasPrivateComponents for RsaPrivateKey
{
    fn d(&self) -> &[u8]
    {
	component!(self -> d)
    }
    fn p(&self) -> &[u8]
    {
	component!(self -> p)
    }
    fn q(&self) -> &[u8]
    {
	component!(self -> q)
    }
    fn dmp1(&self) -> &[u8]
    {
	component!(self -> dmp1)
    }
    fn dmq1(&self) -> &[u8]
    {
	component!(self -> dmq1)
    }
    fn iqmp(&self) -> &[u8]
    {
	component!(self -> iqmp)
    }
}

impl<T> From<Rsa<T>> for RsaPrivateKey
where T: HasPrivate
{
    fn from(key: Rsa<T>) -> Self
    {
	Self::new(
	    key.n(),
	    key.e(),
	    key.d(),
	    key.p().unwrap(),
	    key.q().unwrap(),
	    key.dmp1().unwrap(),
	    key.dmq1().unwrap(),
	    key.iqmp().unwrap()
	)
    }
}

impl From<RsaPrivateKey> for Rsa<Private>
{
    fn from(from: RsaPrivateKey) -> Self
    {
	from.get_rsa_priv().unwrap()
    }
}

impl From<RsaPrivateKey> for RsaPublicKey
{
    fn from(from: RsaPrivateKey) -> Self
    {
	from.get_public_parts()
    }
}

impl PublicKey for RsaPrivateKey
{
    type KeyType = Private;
    type Error = Error;

    fn get_pkey_pub(&self) -> Result<Cow<'_, PKey<Self::KeyType>>, Self::Error>
    {
	Ok(Cow::Owned(PKey::from_rsa(self.get_rsa_priv()?)?))
    }
    
    fn get_rsa_pub(&self) -> Result<Option<Cow<'_, Rsa<Self::KeyType>>>, Self::Error>
    {
	Ok(Some(Cow::Owned(self.get_pkey_pub()?.rsa()?)))
    }
}
impl PrivateKey for RsaPrivateKey{}

impl From<RsaPrivateKey> for Vec<u8>
{
    #[inline] fn from(from: RsaPrivateKey) -> Self
    {
	from.to_bytes()
    }
}

impl TryFrom<Vec<u8>> for RsaPrivateKey
{
    type Error = Error;

    #[inline] fn try_from(from: Vec<u8>) -> Result<Self, Self::Error>
    {
	Self::from_bytes(from)
    }
}
