//! Constants

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
