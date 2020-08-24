//! Utility functions
use std::{
    borrow::{
	Borrow,
	ToOwned,
    },
};

/// Copy slice `src` into `dst` and return the number of elements copied.
#[inline] pub fn copy_slice<T,U,V,W,X>(mut dst: V, src: W) -> usize
where V: AsMut<[T]>,
      W: AsRef<[U]>,
      U: ToOwned<Owned=X>,
      X: Borrow<U> + Into<T>
{

    let mut i=0;
    for (d, s) in dst.as_mut().iter_mut().zip(src.as_ref().iter())
    {
	*d = s.to_owned().into();
	i+=1
    }
    i
}

pub use super::bytes;
