//! Traits for offsets of components

pub struct Starts<T: HasOffsets>(T);

pub trait HasOffsets: Sized
{
    fn starts(&self) -> Starts<Self>;
    fn body_len(&self) -> usize;
}
pub trait HasPublicOffsets: HasOffsets
{
    fn n(&self) -> usize;
    fn e(&self) -> usize;
}
pub trait HasPrivateOffsets: HasPublicOffsets {
    fn d(&self) -> usize;
    fn p(&self) -> usize;
    fn q(&self) -> usize;
    fn dmp1(&self) -> usize;
    fn dmq1(&self) -> usize;
    fn iqmp(&self) -> usize;
}

pub use super::public_offsets::PublicOffsetGroup;
pub use super::private_offsets::PrivateOffsetGroup;

impl<T> Starts<T>
where T: HasPublicOffsets
{
    pub fn n(&self) -> usize
    {
	self.0.n()
    }
    pub fn e(&self) -> usize
    {
	self.0.e()
    }
}

impl<T> From<T> for Starts<T>
where T: HasPublicOffsets
{
    fn from(from: T) -> Self
    {
	Self(from)
    }
}

impl<T> Starts<T>
where T: HasPrivateOffsets
{
    pub fn d(&self) -> usize
    {
	self.0.d()
    }
    pub fn p(&self) -> usize
    {
	self.0.p()
    }
    pub fn q(&self) -> usize
    {
	self.0.q()
    }
    pub fn dmp1(&self) -> usize
    {
	self.0.dmp1()
    }
    pub fn dmq1(&self) -> usize
    {
	self.0.dmq1()
    }
    pub fn iqmp(&self) -> usize
    {
	self.0.iqmp()
    }
}

// Bullshit
use std::{
    cmp::{
	PartialEq,Eq,
    },
    hash::{
	Hash,Hasher,
    },
    fmt::{
	self,
	Debug,
    },
};
impl<T> Copy for Starts<T> where T: Copy + HasOffsets{}
impl<T> Clone for Starts<T> where T: Clone + HasOffsets{#[inline] fn clone(&self) -> Self {Self(self.0.clone())}}
impl<T> Eq for Starts<T> where T: Eq + HasOffsets{}
impl<T> PartialEq for Starts<T> where T: PartialEq + HasOffsets{#[inline] fn eq(&self, other: &Self) -> bool {self.0 == other.0}}
impl<T> Hash for Starts<T>
where T: Hash + HasOffsets
{
    #[inline] fn hash<H: Hasher>(&self, state: &mut H) {
	self.0.hash(state)
    }
}
impl<T> Debug for Starts<T>
    where T: HasOffsets + Debug
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
	write!(f, "Starts ({:?})", self.0)
    }
}
