//! Traits for the key containers
use std::{
    borrow::Cow,
    error,
    convert::Infallible,
};
use openssl::{
    pkey::{
	HasPublic,
	HasPrivate,
	PKey,
    },
    rsa::{
	Rsa,
    },
};

/// A trait for containers that contain public keys
pub trait PublicKey
{
    /// The type of the key
    type KeyType: HasPublic;
    /// Error that can happen from the conversion
    type Error: error::Error;
    /// Get or create a `PKey` that contains the public key
    fn get_pkey_pub(&self) -> Result<Cow<'_, PKey<Self::KeyType>>, Self::Error>;

    /// Get or create an `Rsa` from this public key if possible
    fn get_rsa_pub(&self) -> Result<Option<Cow<'_, Rsa<Self::KeyType>>>, Self::Error>
    {
	Ok(self.get_pkey_pub()?.rsa().ok().map(|x| Cow::Owned(x)))
    }
}

/// A trait for containers that contain private and public keys
pub trait PrivateKey: PublicKey
where <Self as PublicKey>::KeyType: HasPrivate
{
    /// Get or create a `PKey` that contains the private key
    #[inline] fn get_pkey_priv(&self) -> Result<Cow<'_, PKey<<Self as PublicKey>::KeyType>>, <Self as PublicKey>::Error>
    {
	self.get_pkey_pub()
    }
    /// Get or create an `Rsa` from this private key if possible
    #[inline] fn get_rsa_priv(&self) -> Result<Option<Cow<'_, Rsa<Self::KeyType>>>, Self::Error>
    {
	self.get_rsa_pub()
    }
}

impl<T> PublicKey for PKey<T>
where T: HasPublic
{
    type KeyType = T;
    type Error = Infallible;
    fn get_pkey_pub(&self) -> Result<Cow<'_, PKey<Self::KeyType>>, Self::Error>
    {
	Ok(Cow::Borrowed(self))
    }
}

impl<T> PrivateKey for PKey<T>
where T: HasPrivate
{
    fn get_pkey_priv(&self) -> Result<Cow<'_, PKey<<Self as PublicKey>::KeyType>>, <Self as PublicKey>::Error>
    {
	Ok(Cow::Borrowed(self))
    }
}

impl<T> PublicKey for Rsa<T>
where T: HasPublic
{
    type KeyType = T;
    type Error = openssl::error::ErrorStack;
    
    fn get_pkey_pub(&self) -> Result<Cow<'_, PKey<Self::KeyType>>, Self::Error>
    {
	Ok(Cow::Owned(PKey::from_rsa(self.clone())?))
    }
    
    #[inline] fn get_rsa_pub(&self) -> Result<Option<Cow<'_, Rsa<Self::KeyType>>>, Self::Error>
    {
	Ok(Some(Cow::Borrowed(self)))
    }
}

impl<T> PrivateKey for Rsa<T>
where T: HasPrivate
{
    fn get_pkey_priv(&self) -> Result<Cow<'_, PKey<<Self as PublicKey>::KeyType>>, <Self as PublicKey>::Error>
    {
	Ok(Cow::Owned(PKey::from_rsa(self.clone())?))
    }
    
    #[inline] fn get_rsa_priv(&self) -> Result<Option<Cow<'_, Rsa<Self::KeyType>>>, Self::Error>
    {
	Ok(Some(Cow::Borrowed(self)))
    }
}
