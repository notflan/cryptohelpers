//! Bytes related utils
use libc::c_void;
use std::{
    slice,
    mem,
};

/// Copy slice of bytes only. To copy generic slice, use `util::copy_slice()`.
///
/// # Notes
/// `dst` and `src` must not overlap. See [move_slice].
pub fn copy_slice(dst: &mut [u8], src: &[u8]) -> usize
{
    let sz = std::cmp::min(dst.len(),src.len());
    unsafe {
	libc::memcpy(&mut dst[0] as *mut u8 as *mut c_void, &src[0] as *const u8 as *const c_void, sz);
    }
    sz
}

/// Move slice of bytes only
///
/// # Notes
/// `dst` and `src` can overlap.
pub fn move_slice(dst: &mut [u8], src: &[u8]) -> usize
{
    let sz = std::cmp::min(dst.len(),src.len());
    unsafe {
	libc::memmove(&mut dst[0] as *mut u8 as *mut c_void, &src[0] as *const u8 as *const c_void, sz);
    }
    sz
}

/// Get the bytes of a value
pub fn refer<T: ?Sized>(value: &T) -> &[u8]
{
    unsafe {
	slice::from_raw_parts(value as *const T as *const u8, mem::size_of_val(value))
    }
}

/// Get a mutable reference of the bytes of a value
pub fn refer_mut<T: ?Sized>(value: &mut T) -> &mut [u8]
{
    unsafe {
	slice::from_raw_parts_mut(value as *mut T as *mut u8, mem::size_of_val(value))
    }
}

/// Get a type from its bytes
///
/// # Notes
/// This function omits bounds checks in production builds
pub unsafe fn derefer_unchecked<T>(bytes: &[u8]) -> &T
{
    #[cfg(debug_assertions)] assert!(bytes.len() >= mem::size_of::<T>(), "not enough bytes ");
    &*(&bytes[0] as *const u8 as *const T)
}

/// Get a mutable reference to a type from its bytes
///
/// # Notes
/// This function omits bounds checks in production builds
pub unsafe fn derefer_unchecked_mut<T>(bytes: &mut [u8]) -> &mut T
{
    #[cfg(debug_assertions)] assert!(bytes.len() >= mem::size_of::<T>(), "not enough bytes ");
    &mut *(&mut bytes[0] as *mut u8 as *mut T)
}

/// Get a type from its bytes
pub fn derefer<T>(bytes: &[u8]) -> &T
{
    assert!(bytes.len() >= mem::size_of::<T>(), "not enough bytes ");
    unsafe {
	&*(&bytes[0] as *const u8 as *const T)
    }
}

/// Get a mutable reference to a type from its bytes
///
/// # Notes
/// This function omits bounds checks in production builds
pub fn derefer_mut<T>(bytes: &mut [u8]) -> &mut T
{
    assert!(bytes.len() >= mem::size_of::<T>(), "not enough bytes ");
    unsafe {
	&mut *(&mut bytes[0] as *mut u8 as *mut T)
    }
}
