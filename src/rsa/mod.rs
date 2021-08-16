//! RSA related thingies
use super::*;
use std::fmt;
pub use openssl;

use consts::RSA_PADDING as PADDING;

mod containers;
pub use containers::*;

mod offsets;
mod public_offsets;
mod private_offsets;

mod components;
pub use components::*;

macro_rules! component {
    ($self:tt -> $t:tt) => (&$self.data[$self.offset_starts.$t()..($self.offset_starts.$t()+$self.offset.$t())])
}

macro_rules! number {
    (? $self:tt -> $c:tt) => (openssl::bn::BigNum::from_slice($self.$c())?);
    ($self:tt -> $c:tt) => (openssl::bn::BigNum::from_slice($self.$c()).unwrap());
}

mod public;
pub use public::*;

mod private;
pub use private::*;

mod sign;
pub use sign::*;

mod crypt;
pub use crypt::*;

pub use crate::error::rsa::*;
