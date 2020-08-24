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
