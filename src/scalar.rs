use std::{fmt::{Display, Debug}, ops::{Add, Mul}};


// elliptic curve group order
const ORDER: u32 = 65521;
// implement scalar for elliptic curve group
pub struct Scalar{
    pub value: u32
}

impl Scalar {
    pub fn new(value: u32) -> Self {
        // value should modulo g
        Self { value: value % ORDER }
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self { value: (self.value + other.value) % ORDER }
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Self;

    fn add(self, other: &Scalar) -> Self::Output {
        Self { value: (self.value + other.value) % ORDER }
    }
}

impl Add<&Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Self::Output {
        Scalar { value: (self.value + other.value) % ORDER }
    }
}

impl Add<Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Self::Output {
        Scalar { value: (self.value + other.value) % ORDER }
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        Self { value: (self.value * other.value) % ORDER }
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Self;

    fn mul(self, other: &Scalar) -> Self::Output {
        Self { value: (self.value * other.value) % ORDER }
    }
}

impl Mul<&Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Self::Output {
        Scalar { value: (self.value * other.value) % ORDER }
    }
}

impl Debug for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl Display for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
