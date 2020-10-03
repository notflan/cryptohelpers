//! Offsets for a public key container
use super::offsets::*;
use super::*;

#[derive(Clone,Copy,Debug,Eq,PartialEq,Hash,Default)]
#[cfg_attr(feature="serialise", derive(Serialize,Deserialize))]
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
