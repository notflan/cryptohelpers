//! Constants used throughout
//!
//! # Notes
//! Probably best to not change these unless you know what you're doing.

/// Default buffer size for most things
pub const BUFFER_SIZE: usize = 4096;

/// Size of SHA256 hash checksum in bytes
pub const SHA256_SIZE: usize = 32;

/// Password saltsize
pub const PASSWORD_SALTSIZE: usize = 32;

/// Password keysize
pub const PASSWORD_KEYSIZE: usize = 32;

/// Password rounds
pub const PASSWORD_ROUNDS: u32 = 4096;

/// Aes key size in bytes
pub const AES_KEYSIZE: usize = 16;

/// Aes IV size in bytes
pub const AES_IVSIZE: usize = 16;

/// The number of bits used for RSA key
pub const RSA_KEY_BITS: u32 = 4096;

/// Size of an RSA signature
pub const RSA_SIG_SIZE: usize = 512;

/// The number of bytes the RSA padding requires
pub const RSA_PADDING_NEEDS: usize = 11;

/// The padding used for RSA operations
#[cfg(feature="rsa")] 
pub const RSA_PADDING: openssl::rsa::Padding = openssl::rsa::Padding::PKCS1;
