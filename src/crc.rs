//! CRC64 algorithm

use super::consts;
#[allow(unused_imports)]
use std::{
    marker::Unpin,
    io,
};
use crc::{
    crc64,
    Hasher64,
};
#[cfg(feature="async")]
use tokio::io::{
    AsyncRead,
    AsyncReadExt,
};
use consts::BUFFER_SIZE;

/// Compute a crc64 checksum from a slice.
pub fn compute_slice(data: impl AsRef<[u8]>) -> u64
{
    let mut digest = crc64::Digest::new(crc64::ECMA);
    digest.write(data.as_ref());
    digest.sum64()
}

/// Read a full stream into a CRC64 checksum
#[cfg(feature="async")] 
pub async fn compute_stream<T>(from: &mut T) -> io::Result<u64>
    where T: AsyncRead + Unpin + ?Sized
{
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut read;
    let mut digest = crc64::Digest::new(crc64::ECMA);
    while (read = from.read(&mut buffer[..]).await?, read!=0).1
    {
	digest.write(&buffer[..read]);
    }
    Ok(digest.sum64())
}

/// Read a full stream into a CRC64 checksum
pub async fn compute_stream_sync<T>(from: &mut T) -> io::Result<u64>
    where T: io::Read + Unpin + ?Sized
{
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut read;
    let mut digest = crc64::Digest::new(crc64::ECMA);
    while (read = from.read(&mut buffer[..])?, read!=0).1
    {
	digest.write(&buffer[..read]);
    }
    Ok(digest.sum64())
}
