//! Offsets for a public key container
use super::offsets::*;

#[repr(C, packed)]
#[derive(Clone,Copy,Debug,Eq,PartialEq,Hash,Default)]
pub struct PublicOffsetGroup
{
    pub n: usize,
    pub e: usize,
}

impl HasOffsets for PublicOffsetGroup
{
    fn starts(&self) -> Starts<Self>
    {
	Self {
	    n: 0,
	    e: self.n,
	}.into()
    }
    fn body_len(&self) -> usize
    {
	self.n+self.e
    }
}

impl HasPublicOffsets for PublicOffsetGroup
{
    fn n(&self) -> usize
    {
	self.n
    }
    fn e(&self) -> usize
    {
	self.e
    }
}
