//! Private offsets
use super::offsets::*;

#[derive(Clone,Copy,Debug,Eq,PartialEq,Hash,Default)]
pub struct PrivateOffsetGroup
{
    pub n: usize,
    pub e: usize,
    pub d: usize,
    pub p: usize,
    pub q: usize,
    pub dmp1: usize,
    pub dmq1: usize,
    pub iqmp: usize,
}

impl HasOffsets for PrivateOffsetGroup
{
    fn starts(&self) -> Starts<Self>
    {
	Self {
	    n:    0,
	    e:    self.n,
	    d:    self.n+self.e,
	    p:    self.n+self.e+self.d,
	    q:    self.n+self.e+self.d+self.p,
	    dmp1: self.n+self.e+self.d+self.p+self.q,
	    dmq1: self.n+self.e+self.d+self.p+self.q+self.dmp1,
	    iqmp: self.n+self.e+self.d+self.p+self.q+self.dmp1+self.dmq1,
	}.into()
    }

    fn body_len(&self) -> usize
    {
	self.n+self.e+self.d+self.p+self.q+self.dmp1+self.dmq1+self.iqmp
    }
}

impl HasPublicOffsets for PrivateOffsetGroup
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

impl HasPrivateOffsets for PrivateOffsetGroup
{
    fn d(&self) -> usize
    {
	self.d
    }
    fn p(&self) -> usize
    {
	self.p
    }
    fn q(&self) -> usize
    {
	self.q
    }
    fn dmp1(&self) -> usize
    {
	self.dmp1
    }
    fn dmq1(&self) -> usize
    {
	self.dmq1
    }
    fn iqmp(&self) -> usize
    {
	self.iqmp
    }
}
