//! Crypto transforms
use super::*;
#[allow(unused_imports)]
use std::{
    convert::TryFrom,
    marker::Unpin,
    io::{
	Write,
	Read,
    },
};
use openssl::{
    pkey::HasPrivate,
};
#[cfg(feature="async")]
use tokio::{
    io::{
	AsyncWrite,
	AsyncRead,
    },
    prelude::*,
};

use consts::RSA_PADDING_NEEDS as PADDING_NEEDS;

/// Encrypt a slice `data` to a new output vector with key `key`
pub fn encrypt_slice_to_vec<T,K>(data: T, key: &K) -> Result<Vec<u8>, Error>
where T: AsRef<[u8]>,
      K: PublicKey + ?Sized,
{
    let data = data.as_ref();
    let mut output = Vec::with_capacity(data.len());
    encrypt_slice_sync(data, key, &mut output)?;
    Ok(output)
}

/// Decrypt a slice `data` to a new output vector with key `key`
pub fn decrypt_slice_to_vec<T,K>(data: T, key: &K) -> Result<Vec<u8>, Error>
where T: AsRef<[u8]>,
      K: PrivateKey + ?Sized,
<K as PublicKey>::KeyType: HasPrivate,
{
    let data = data.as_ref();
    let mut output = Vec::with_capacity(data.len());
    decrypt_slice_sync(data, key, &mut output)?;
    Ok(output)
}

/// Encrypt a stream `data` into `output` with `key`. Return the number of bytes *read*.
#[cfg(feature="async")] 
pub async fn encrypt<T,K,U>(data: &mut T, key: &K, output: &mut U) -> Result<usize, Error>
where T: AsyncRead + Unpin + ?Sized,
      K: PublicKey + ?Sized,
      U: AsyncWrite + Unpin + ?Sized
{
    let key = key.get_rsa_pub().map_err(|_| Error::Key)?.ok_or(Error::Key)?;
    let key_size = usize::try_from(key.size())?;

    let max_size = key_size - PADDING_NEEDS;

    let mut read_buffer = vec![0u8; max_size];
    let mut crypt_buffer = vec![0u8; key_size];

    let mut read;
    let mut done=0;
    while {read = data.read(&mut read_buffer[..]).await?; read!=0} {
	done+=read;
	read = key.public_encrypt(&read_buffer[..read], &mut crypt_buffer[..], PADDING).map_err(|_| Error::Encrypt)?;
	output.write_all(&crypt_buffer[..read]).await?;
    }
    
    Ok(done)
}

/// Encrypt a slice `data` into `output` with `key`. Return the number of bytes *written*.
#[cfg(feature="async")] 
pub async fn encrypt_slice<T,K,U>(data: T, key: &K, output: &mut U) -> Result<usize, Error>
where T: AsRef<[u8]>,
      K: PublicKey + ?Sized,
      U: AsyncWrite + Unpin + ?Sized
{
    let key = key.get_rsa_pub().map_err(|_| Error::Key)?.ok_or(Error::Key)?;
    let key_size = usize::try_from(key.size())?;

    let mut crypt_buffer = vec![0u8; key_size];

    let read = key.public_encrypt(data.as_ref(), &mut crypt_buffer[..], PADDING).map_err(|_| Error::Encrypt)?;
    output.write_all(&crypt_buffer[..read]).await?;

    Ok(read)
}
/// Encrypt a stream `data` into `output` with `key`. Return the number of bytes *read*.
pub fn encrypt_sync<T,K,U>(data: &mut T, key: &K, output: &mut U) -> Result<usize, Error>
where T: Read + ?Sized,
      K: PublicKey + ?Sized,
      U: Write + ?Sized
{
    let key = key.get_rsa_pub().map_err(|_| Error::Key)?.ok_or(Error::Key)?;
    let key_size = usize::try_from(key.size())?;

    let max_size = key_size - PADDING_NEEDS;

    let mut read_buffer = vec![0u8; max_size];
    let mut crypt_buffer = vec![0u8; key_size];

    let mut read;
    let mut done=0;
    while {read = data.read(&mut read_buffer[..])?; read!=0} {
	done+=read;
	read = key.public_encrypt(&read_buffer[..read], &mut crypt_buffer[..], PADDING).map_err(|_| Error::Encrypt)?;
	output.write_all(&crypt_buffer[..read])?;
    }
    
    Ok(done)
}

/// Encrypt a slice `data` into `output` with `key`. Return the number of bytes *written*.
pub fn encrypt_slice_sync<T,K,U>(data: T, key: &K, output: &mut U) -> Result<usize, Error>
where T: AsRef<[u8]>,
      K: PublicKey + ?Sized,
      U: Write + ?Sized
{
    let key = key.get_rsa_pub().map_err(|_| Error::Key)?.ok_or(Error::Key)?;
    let key_size = usize::try_from(key.size())?;

    let mut crypt_buffer = vec![0u8; key_size];

    let read = key.public_encrypt(data.as_ref(), &mut crypt_buffer[..], PADDING).map_err(|_| Error::Encrypt)?;
    output.write_all(&crypt_buffer[..read])?;

    Ok(read)
}

/// Decrypt slice `data` into `output` with `key`. Return the number of bytes *written*.
#[cfg(feature="async")] 
pub async fn decrypt_slice<T,K,U>(data: T, key: &K, output: &mut U) -> Result<usize, Error>
where T: AsRef<[u8]>,
      K: PrivateKey + ?Sized,
      U: AsyncWrite + Unpin + ?Sized,
<K as PublicKey>::KeyType: HasPrivate,
{
    
    let key = key.get_rsa_priv().map_err(|_| Error::Key)?.ok_or(Error::Key)?;
    let key_size = usize::try_from(key.size())?;

    let mut crypt_buffer = vec![0u8; key_size];

    let read = key.private_decrypt(data.as_ref(), &mut crypt_buffer[..], PADDING).map_err(|_| Error::Decrypt)?;
    output.write_all(&crypt_buffer[..read]).await?;

    Ok(read)
}

/// Decrypt a stream `data` into `output` with `key`. Return the number of bytes *read*.
#[cfg(feature="async")] 
pub async fn decrypt<T,K,U>(data: &mut T, key: &K, output: &mut U) -> Result<usize, Error>
where T: AsyncRead + Unpin + ?Sized,
      K: PrivateKey + ?Sized,
      U: AsyncWrite + Unpin + ?Sized,
<K as PublicKey>::KeyType: HasPrivate,
{
    let key = key.get_rsa_priv().map_err(|_| Error::Key)?.ok_or(Error::Key)?;
    let key_size = usize::try_from(key.size())?;

    let max_size = key_size - PADDING_NEEDS;

    let mut read_buffer = vec![0u8; max_size];
    let mut crypt_buffer = vec![0u8; key_size];

    let mut read;
    let mut done=0;
    while {read = data.read(&mut read_buffer[..]).await?; read!=0} {
	done+=read;
	read = key.private_decrypt(&read_buffer[..read], &mut crypt_buffer[..], PADDING).map_err(|_| Error::Decrypt)?;
	output.write_all(&crypt_buffer[..read]).await?;
    }
    
    Ok(done)

}

/// Decrypt slice `data` into `output` with `key`. Return the number of bytes *written*.
pub fn decrypt_slice_sync<T,K,U>(data: T, key: &K, output: &mut U) -> Result<usize, Error>
where T: AsRef<[u8]>,
      K: PrivateKey + ?Sized,
      U: Write + ?Sized,
<K as PublicKey>::KeyType: HasPrivate,
{
    
    let key = key.get_rsa_priv().map_err(|_| Error::Key)?.ok_or(Error::Key)?;
    let key_size = usize::try_from(key.size())?;

    let mut crypt_buffer = vec![0u8; key_size];

    let read = key.private_decrypt(data.as_ref(), &mut crypt_buffer[..], PADDING).map_err(|_| Error::Decrypt)?;
    output.write_all(&crypt_buffer[..read])?;

    Ok(read)
}

/// Decrypt a stream `data` into `output` with `key`. Return the number of bytes *read*.
pub fn decrypt_sync<T,K,U>(data: &mut T, key: &K, output: &mut U) -> Result<usize, Error>
where T: Read + ?Sized,
      K: PrivateKey + ?Sized,
      U: Write + ?Sized,
<K as PublicKey>::KeyType: HasPrivate,
{
    let key = key.get_rsa_priv().map_err(|_| Error::Key)?.ok_or(Error::Key)?;
    let key_size = usize::try_from(key.size())?;

    let max_size = key_size - PADDING_NEEDS;

    let mut read_buffer = vec![0u8; max_size];
    let mut crypt_buffer = vec![0u8; key_size];

    let mut read;
    let mut done=0;
    while {read = data.read(&mut read_buffer[..])?; read!=0} {
	done+=read;
	read = key.private_decrypt(&read_buffer[..read], &mut crypt_buffer[..], PADDING).map_err(|_| Error::Decrypt)?;
	output.write_all(&crypt_buffer[..read])?;
    }
    
    Ok(done)

}
