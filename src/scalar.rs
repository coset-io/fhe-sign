use std::{clone::Clone, fmt::{Debug, Display}, ops::{Add, Div, Mul, Neg, Sub}};
use num_bigint::{BigUint, BigInt, Sign};
use hex;

// Scalars are elements in the finite field modulo n (secp256k1 curve order).
// The curve order is a 256-bit number representing the number of points on the curve.
const CURVE_ORDER: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

// Helper function to get curve order as BigUint
fn get_curve_order() -> BigUint {
    // Remove "0x" prefix and convert hex string to BigUint
    let hex_str = CURVE_ORDER.trim_start_matches("0x");
    BigUint::parse_bytes(hex_str.as_bytes(), 16).unwrap()
}

pub struct Scalar {
    pub value: BigUint,
    pub order: BigUint,
}

impl Scalar {
    pub fn new(value: BigUint) -> Self {
        let order = get_curve_order();
        Self {
            value: value % &order,
            order
        }
    }

    // Create a scalar from a signed integer
    pub fn from_i32(value: i32) -> Self {
        let order = get_curve_order();
        let value = if value < 0 {
            // For negative values, we add the order until we get a positive number
            let abs_val = (-value) as u32;
            let abs_big = BigUint::from(abs_val);
            &order - (abs_big % &order)
        } else {
            BigUint::from(value as u32) % &order
        };
        Self { value, order }
    }

    // Calculate the modular multiplicative inverse using Extended Euclidean Algorithm
    pub fn inverse(&self) -> Self {
        if self.value == BigUint::from(0u32) {
            panic!("Cannot compute inverse of zero");
        }

        let mut t = BigInt::from(0);
        let mut newt = BigInt::from(1);
        let mut r = BigInt::from(self.order.clone());
        let mut newr = BigInt::from(self.value.clone());

        while newr != BigInt::from(0) {
            let quotient = &r / &newr;
            let temp_t = t;
            t = newt.clone();
            newt = temp_t - &quotient * &newt;

            let temp_r = r;
            r = newr.clone();
            newr = temp_r - quotient * newr;
        }

        // If r > 1, n and a are not coprime, no inverse exists
        if r > BigInt::from(1) {
            panic!("Modular inverse does not exist");
        }

        // Make positive
        while t < BigInt::from(0) {
            t = t + BigInt::from(self.order.clone());
        }

        // Convert back to BigUint and reduce mod n
        let value = match t.to_biguint() {
            Some(v) => v % &self.order,
            None => panic!("Failed to convert to unsigned"),
        };

        Self { value, order: self.order.clone() }
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self {
            value: (self.value + other.value) % &self.order,
            order: self.order
        }
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Self;

    fn add(self, other: &Scalar) -> Self::Output {
        Self {
            value: (self.value + &other.value) % &self.order,
            order: self.order
        }
    }
}

impl Add<&Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Self::Output {
        Scalar {
            value: (&self.value + &other.value) % &self.order,
            order: self.order.clone()
        }
    }
}

impl Add<Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Self::Output {
        Scalar {
            value: (&self.value + other.value) % &self.order,
            order: self.order.clone()
        }
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            value: &self.order - (self.value % &self.order),
            order: self.order
        }
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        let mut result = self.value;
        if result < other.value {
            result = result + &self.order;
        }
        Self {
            value: (result - other.value) % &self.order,
            order: self.order
        }
    }
}

impl Sub<&Scalar> for Scalar {
    type Output = Self;

    fn sub(self, other: &Scalar) -> Self::Output {
        let mut result = self.value;
        if result < other.value {
            result = result + &self.order;
        }
        Self {
            value: (result - &other.value) % &self.order,
            order: self.order
        }
    }
}

impl Sub<&Scalar> for &Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Self::Output {
        let mut result = self.value.clone();
        if result < other.value {
            result = result + &self.order;
        }
        Scalar {
            value: (result - &other.value) % &self.order,
            order: self.order.clone()
        }
    }
}

impl Sub<Scalar> for &Scalar {
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Self::Output {
        let mut result = self.value.clone();
        if result < other.value {
            result = result + &self.order;
        }
        Scalar {
            value: (result - other.value) % &self.order,
            order: self.order.clone()
        }
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        Self {
            value: (self.value * other.value) % &self.order,
            order: self.order
        }
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Self;

    fn mul(self, other: &Scalar) -> Self::Output {
        Self {
            value: (self.value * &other.value) % &self.order,
            order: self.order
        }
    }
}

impl Mul<&Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Self::Output {
        Scalar {
            value: (&self.value * &other.value) % &self.order,
            order: self.order.clone()
        }
    }
}

impl Mul<Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, other: Scalar) -> Self::Output {
        Scalar {
            value: (&self.value * other.value) % &self.order,
            order: self.order.clone()
        }
    }
}

impl Div for Scalar {
    type Output = Self;

    fn div(self, other: Self) -> Self::Output {
        if other.value == BigUint::from(0u32) {
            panic!("Division by zero");
        }
        // a/b = a * b^(-1)
        self * other.inverse()
    }
}

impl Div<&Scalar> for Scalar {
    type Output = Self;

    fn div(self, other: &Scalar) -> Self::Output {
        if other.value == BigUint::from(0u32) {
            panic!("Division by zero");
        }
        self * other.inverse()
    }
}

impl Div<&Scalar> for &Scalar {
    type Output = Scalar;

    fn div(self, other: &Scalar) -> Self::Output {
        if other.value == BigUint::from(0u32) {
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
        Self {
            value: self.value.clone(),
            order: self.order.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        // Test value equal to curve order
        let order = get_curve_order();
        let a = Scalar::new(order.clone());
        assert_eq!(a.value, BigUint::from(0u32));

        // Test negative value through from_i32
        let b = Scalar::from_i32(-1);
        let expected = &order - BigUint::from(1u32);
        assert_eq!(b.value, expected);

        // Test value larger than curve order
        let large_value = order + BigUint::from(1u32);
        let c = Scalar::new(large_value);
        assert_eq!(c.value, BigUint::from(1u32));
    }

    #[test]
    fn test_neg() {
        let a = Scalar::new(BigUint::from(1u32));
        let b = -a;
        let expected = get_curve_order() - BigUint::from(1u32);
        assert_eq!(b.value, expected);
    }

    #[test]
    fn test_addition() {
        let a = Scalar::new(BigUint::from(2u32));
        let b = Scalar::new(BigUint::from(3u32));
        let c = a + b;
        assert_eq!(c.value, BigUint::from(5u32));
    }

    #[test]
    fn test_addition_overflow() {
        let order = get_curve_order();
        let a = Scalar::new(order.clone() - BigUint::from(1u32));
        let b = Scalar::new(BigUint::from(2u32));
        let c = &a + &b;
        assert_eq!(c.value, BigUint::from(1u32));
    }

    #[test]
    fn test_subtraction() {
        let a = Scalar::new(BigUint::from(5u32));
        let b = Scalar::new(BigUint::from(3u32));
        let c = a - b;
        assert_eq!(c.value, BigUint::from(2u32));
    }

    #[test]
    fn test_subtraction_overflow() {
        let a = Scalar::new(BigUint::from(0u32));
        let b = Scalar::new(BigUint::from(1u32));
        let c = &a - &b;
        let expected = get_curve_order() - BigUint::from(1u32);
        assert_eq!(c.value, expected);
    }

    #[test]
    fn test_multiplication() {
        let a = Scalar::new(BigUint::from(2u32));
        let b = Scalar::new(BigUint::from(3u32));
        let c = a * b;
        assert_eq!(c.value, BigUint::from(6u32));
    }

    #[test]
    fn test_multiplication_overflow() {
        let order = get_curve_order();
        let a = Scalar::new(order.clone() - BigUint::from(1u32));
        let b = Scalar::new(BigUint::from(2u32));
        let c = &a * &b;
        assert_eq!(c.value, order - BigUint::from(2u32));
    }

    #[test]
    fn test_inverse() {
        // Test inverse of 2
        let a = Scalar::new(BigUint::from(2u32));
        let a_inv = a.inverse();
        assert_eq!((a * a_inv).value, BigUint::from(1u32));

        // Test inverse of a larger number
        let b = Scalar::new(BigUint::from(12345u32));
        let b_inv = b.inverse();
        assert_eq!((b * b_inv).value, BigUint::from(1u32));
    }

    #[test]
    fn test_division() {
        // Test 6/2 = 3
        let a = Scalar::new(BigUint::from(6u32));
        let b = Scalar::new(BigUint::from(2u32));
        assert_eq!((&a / &b).value, BigUint::from(3u32));
        assert_eq!((&b / &a), a.inverse() * b);

        // Test with larger numbers
        let c = Scalar::new(BigUint::from(12345u32));
        let d = Scalar::new(BigUint::from(67u32));
        let result = &c / &d;
        assert_eq!((result * d).value, c.value);
    }

    #[test]
    #[should_panic]
    fn test_division_by_zero() {
        let a = Scalar::new(BigUint::from(5u32));
        let b = Scalar::new(BigUint::from(0u32));
        let _ = a / b;
    }
}
