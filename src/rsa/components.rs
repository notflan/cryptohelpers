//! Traits for objects with RSA key components
use openssl::{
    bn::BigNum,
};
pub trait HasComponents
{
    fn raw(&self) -> &[u8];
}

pub trait HasPublicComponents: HasComponents
{
    fn e(&self) -> &[u8];
    fn n(&self) -> &[u8];
    
    /// Get the modulus component as a new `BigNum`.
    ///
    /// # Notes
    /// This can panic if the internal state of the instance is incorrect
    #[inline] fn num_n(&self) -> BigNum
    {
	BigNum::from_slice(self.n()).unwrap() //we assume things like this succeed because we assume the internal stat is consistant
    }

    /// Get the exponent component as a new `BigNum`
    ///
    /// # Notes
    /// This can panic if the internal state of the instance is incorrect
    #[inline] fn num_e(&self) -> BigNum
    {
	BigNum::from_slice(self.e()).unwrap()
    }
}

pub trait HasPrivateComponents: HasPublicComponents
{
    fn d(&self) -> &[u8];
    fn p(&self) -> &[u8];
    fn q(&self) -> &[u8];
    fn dmp1(&self) -> &[u8];
    fn dmq1(&self) -> &[u8];
    fn iqmp(&self) -> &[u8];

    #[inline] fn num_d(&self) -> BigNum
    {
	BigNum::from_slice(self.d()).unwrap()
    }
    #[inline] fn num_p(&self) -> BigNum
    {
	BigNum::from_slice(self.p()).unwrap()
    }
    #[inline] fn num_q(&self) -> BigNum
    {
	BigNum::from_slice(self.q()).unwrap()
    }
    #[inline] fn num_dmp1(&self) -> BigNum
    {
	BigNum::from_slice(self.dmp1()).unwrap()
    }
    #[inline] fn num_dmq1(&self) -> BigNum
    {
	BigNum::from_slice(self.dmq1()).unwrap()
    }
    #[inline] fn num_iqmp(&self) -> BigNum
    {
	BigNum::from_slice(self.iqmp()).unwrap()
    }
}
