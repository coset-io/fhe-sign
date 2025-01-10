use std::{clone::Clone, fmt::{Debug, Display}, ops::{Add, Div, Mul, Neg, Sub}};

// Scalars are elements in the finite field modulo n(group order).

// curve group order
// const CURVE_ORDER: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
// todo: use real curve order, how to handle big number?
const CURVE_ORDER: u32 = 65521;

pub struct Scalar{
    pub value: u32,
    pub order: u32,
}

impl Scalar {
    pub fn new(value: i32, order: u32) -> Self {
        Self { value: value.rem_euclid(order as i32) as u32, order }
    }

    pub fn inverse(&self) -> Self {
        // Extended Euclidean Algorithm to find modular multiplicative inverse
        let mut t = 0i32;
        let mut newt = 1i32;
        let mut r = self.order as i32;
        let mut newr = self.value as i32;

        while newr != 0 {
            let quotient = r / newr;
            (t, newt) = (newt, t - quotient * newt);
            (r, newr) = (newr, r - quotient * newr);
        }

        // Convert back to positive value if negative
        if t < 0 {
            t = t + self.order as i32;
        }

        Self::new(t, self.order)
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self { value: (self.value + other.value) % self.order, order: self.order }
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Self;

    fn add(self, other: &Scalar) -> Self::Output {
        Self { value: (self.value + other.value) % self.order, order: self.order }
    }
}

impl Add<&Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Self::Output {
        Scalar { value: (self.value + other.value) % self.order, order: self.order }
    }
}

impl Add<Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Self::Output {
        Scalar { value: (self.value + other.value) % self.order, order: self.order }
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let value_i32 = self.value as i32;
        Self { value: (-value_i32).rem_euclid(self.order as i32) as u32, order: self.order }
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        let self_i32 = self.value as i32;
        let other_i32 = other.value as i32;
        Self { value: (self_i32 - other_i32).rem_euclid(self.order as i32) as u32, order: self.order }
    }
}

impl Sub<&Scalar> for Scalar {
    type Output = Self;

    fn sub(self, other: &Scalar) -> Self::Output {
        let self_i32 = self.value as i32;
        let other_i32 = other.value as i32;
        Self { value: (self_i32 - other_i32).rem_euclid(self.order as i32) as u32, order: self.order }
    }
}

impl Sub<&Scalar> for &Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Self::Output {
        let self_i32 = self.value as i32;
        let other_i32 = other.value as i32;
        Scalar { value: (self_i32 - other_i32).rem_euclid(self.order as i32) as u32, order: self.order }
    }
}

impl Sub<Scalar> for &Scalar {
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Self::Output {
        let self_i32 = self.value as i32;
        let other_i32 = other.value as i32;
        Scalar { value: (self_i32 - other_i32).rem_euclid(self.order as i32) as u32, order: self.order }
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        Self { value: (self.value * other.value) % self.order, order: self.order }
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Self;

    fn mul(self, other: &Scalar) -> Self::Output {
        Scalar { value: (self.value * other.value) % self.order, order: self.order }
    }
}

impl Mul<&Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Self::Output {
        Scalar { value: (self.value * other.value) % self.order, order: self.order }
    }
}

impl Mul<Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, other: Scalar) -> Self::Output {
        Scalar { value: (self.value * other.value) % self.order, order: self.order }
    }
}

impl Div for Scalar {
    type Output = Self;

    fn div(self, other: Self) -> Self::Output {
        if other.value == 0 {
            panic!("Division by zero");
        }
        // a/b = a * b^(-1)
        self * other.inverse()
    }
}

impl Div<&Scalar> for Scalar {
    type Output = Self;

    fn div(self, other: &Scalar) -> Self::Output {
        if other.value == 0 {
            panic!("Division by zero");
        }
        self * other.inverse()
    }
}

impl Div<&Scalar> for &Scalar {
    type Output = Scalar;

    fn div(self, other: &Scalar) -> Self::Output {
        if other.value == 0 {
            panic!("Division by zero");
        }
        self * other.inverse()
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

impl Clone for Scalar {
    fn clone(&self) -> Self {
        Self { value: self.value, order: self.order }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let a = Scalar::new(65521, CURVE_ORDER);
        assert_eq!(a.value, 0);
        let b = Scalar::new(-1, CURVE_ORDER);
        assert_eq!(b.value, 65520);
        let c = Scalar::new(65522, CURVE_ORDER);
        assert_eq!(c.value, 1);
    }

    #[test]
    fn test_neg() {
        let a = Scalar::new(1, CURVE_ORDER);
        let b = -a;
        assert_eq!(b.value, 65520);
    }

    #[test]
    fn test_addition() {
        let a = Scalar::new(2, CURVE_ORDER);
        let b = Scalar::new(3, CURVE_ORDER);
        let c = a + b;
        assert_eq!(c.value, 5);
    }

    #[test]
    fn test_addition_overflow() {
        let a = Scalar::new(65520, CURVE_ORDER);
        let b = Scalar::new(1, CURVE_ORDER);
        let c = &a + &b;
        assert_eq!(c.value, 0);

        let d = Scalar::new(2, CURVE_ORDER);
        let e = &a + &d;
        assert_eq!(e.value, 1);
    }

    #[test]
    fn test_subtraction() {
        let a = Scalar::new(5, CURVE_ORDER);
        let b = Scalar::new(3, CURVE_ORDER);
        let c = a - b;
        assert_eq!(c.value, 2);
    }

    #[test]
    fn test_subtraction_overflow() {
        let a = Scalar::new(0, CURVE_ORDER);
        let b = Scalar::new(1, CURVE_ORDER);
        let c = &a - &b;
        assert_eq!(c.value, 65520);
    }

    #[test]
    fn test_multiplication() {
        let a = Scalar::new(2, CURVE_ORDER);
        let b = Scalar::new(3, CURVE_ORDER);
        let c = a * b;
        assert_eq!(c.value, 6);
    }

    #[test]
    fn test_multiplication_overflow() {
        let a = Scalar::new(32761, CURVE_ORDER);
        let b = Scalar::new(2, CURVE_ORDER);
        let c = &a * &b;
        assert_eq!(c.value, 1);
    }

    #[test]
    fn test_inverse() {
        // Test inverse of 2 (mod 65521)
        let a = Scalar::new(2, CURVE_ORDER);
        let a_inv = a.inverse();
        assert_eq!((a * a_inv).value, 1); // 2 * 32761 ≡ 1 (mod 65521)

        // Test inverse of 3 (mod 65521)
        let b = Scalar::new(3, CURVE_ORDER);
        let b_inv = b.inverse();
        assert_eq!((b * b_inv).value, 1); // 3 * 43681 ≡ 1 (mod 65521)
    }

      #[test]
    fn test_inverse_full_cycle() {
        let a = Scalar::new(12345, CURVE_ORDER);
        let a_inv = a.inverse();
        assert_eq!((a.clone() * a_inv.clone()).value, 1);

        let b = Scalar::new(65519, CURVE_ORDER); // 65519 * 65519 mod 65521 = 1
        let b_inv = b.inverse();
        assert_eq!((b.clone() * b_inv.clone()).value, 1);
    }

    #[test]
    fn test_division() {
        // Test 6/2 ≡ 3 (mod 65521)
        let a = Scalar::new(6, CURVE_ORDER);
        let b = Scalar::new(2, CURVE_ORDER);
        assert_eq!((a / b).value, 3);

        // Test 15/3 ≡ 5 (mod 65521)
        let c = Scalar::new(15, CURVE_ORDER);
        let d = Scalar::new(3, CURVE_ORDER);
        assert_eq!((c / d).value, 5);

        // Test division by reference
        let e = Scalar::new(8, CURVE_ORDER);
        let f = Scalar::new(4, CURVE_ORDER);
        assert_eq!((e / &f).value, 2);

        // Test division by reference
        let g = Scalar::new(4, CURVE_ORDER);
        let h = Scalar::new(8, CURVE_ORDER);
        let i = Scalar::new(2, CURVE_ORDER);
        let i_inv = i.inverse();
        assert_eq!((g / h).value, i_inv.value);


    }

    #[test]
    #[should_panic]
    fn test_division_by_zero() {
        let a = Scalar::new(5, CURVE_ORDER);
        let b = Scalar::new(0, CURVE_ORDER);
        let _ = a / b;
    }
}
