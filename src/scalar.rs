use num_bigint::BigUint;
use crate::field::FieldElement;

/// The prime field size (p) for secp256k1 curve
const FIELD_SIZE: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";

/// The curve order (n) for secp256k1 curve
const CURVE_ORDER: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

/// Returns the field size as a BigUint
pub fn get_field_size() -> BigUint {
    BigUint::parse_bytes(&FIELD_SIZE[2..].as_bytes(), 16).unwrap()
}

/// Returns the curve order as a BigUint
pub fn get_curve_order() -> BigUint {
    BigUint::parse_bytes(&CURVE_ORDER[2..].as_bytes(), 16).unwrap()
}

/// Creates a new field element in the base field (mod p).
pub fn new_base_field(value: BigUint) -> FieldElement {
    FieldElement::new(value, get_field_size())
}

/// Creates a new field element in the scalar field (mod n).
pub fn new_scalar_field(value: BigUint) -> FieldElement {
    FieldElement::new(value, get_curve_order())
}

/// Represents a scalar value in the secp256k1 curve's scalar field.
/// This is specifically for scalar multiplication operations in ECC.
#[derive(Clone, Debug, PartialEq)]
pub struct Scalar(FieldElement);

impl Scalar {
    /// Creates a new scalar value, automatically reducing it modulo the curve order.
    pub fn new(value: BigUint) -> Self {
        Self(new_scalar_field(value))
    }

    /// Creates a scalar from bytes in big-endian format.
    /// The bytes are interpreted as an unsigned integer and reduced modulo the curve order.
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        let value = BigUint::from_bytes_be(bytes);
        Self::new(value)
    }

    /// Creates a scalar from bytes in little-endian format.
    /// The bytes are interpreted as an unsigned integer and reduced modulo the curve order.
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        let value = BigUint::from_bytes_le(bytes);
        Self::new(value)
    }

    /// Returns the scalar value as a big-endian byte array.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        self.value().to_bytes_be()
    }

    /// Returns the scalar value as a little-endian byte array.
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.value().to_bytes_le()
    }

    /// Returns the zero scalar.
    pub fn zero() -> Self {
        Self::new(BigUint::from(0u32))
    }

    /// Returns the one scalar (multiplicative identity).
    pub fn one() -> Self {
        Self::new(BigUint::from(1u32))
    }

    /// Creates a scalar from a signed integer.
    pub fn from_i32(value: i32) -> Self {
        let order = get_curve_order();
        let value = if value < 0 {
            let abs_val = (-value) as u32;
            let abs_big = BigUint::from(abs_val);
            &order - (abs_big % &order)
        } else {
            BigUint::from(value as u32) % &order
        };
        Self::new(value)
    }

    /// Returns the underlying field element.
    pub fn as_field_element(&self) -> &FieldElement {
        &self.0
    }

    /// Returns the value of the scalar.
    pub fn value(&self) -> &BigUint {
        self.0.value()
    }

    /// Adds two scalars modulo the curve order.
    pub fn add(&self, other: &Scalar) -> Scalar {
        Self(self.0.clone() + &other.0)
    }

    /// Subtracts two scalars modulo the curve order.
    pub fn sub(&self, other: &Scalar) -> Scalar {
        Self(self.0.clone() - &other.0)
    }

    /// Multiplies two scalars modulo the curve order.
    pub fn mul(&self, other: &Scalar) -> Scalar {
        Self(self.0.clone() * &other.0)
    }

    /// Computes the additive inverse of the scalar.
    pub fn neg(&self) -> Scalar {
        Self(-self.0.clone())
    }

    /// Computes the multiplicative inverse of the scalar.
    pub fn inverse(&self) -> Scalar {
        Self(self.0.inverse())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_addition() {
        let a = Scalar::new(BigUint::from(5u32));
        let b = Scalar::new(BigUint::from(3u32));
        let c = a.add(&b);
        assert_eq!(c.value(), &BigUint::from(8u32));
    }

    #[test]
    fn test_scalar_subtraction() {
        let a = Scalar::new(BigUint::from(5u32));
        let b = Scalar::new(BigUint::from(3u32));
        let c = a.sub(&b);
        assert_eq!(c.value(), &BigUint::from(2u32));
    }

    #[test]
    fn test_scalar_multiplication() {
        let a = Scalar::new(BigUint::from(5u32));
        let b = Scalar::new(BigUint::from(3u32));
        let c = a.mul(&b);
        assert_eq!(c.value(), &BigUint::from(15u32));
    }

    #[test]
    fn test_scalar_negation() {
        let a = Scalar::new(BigUint::from(5u32));
        let neg_a = a.neg();
        let sum = a.add(&neg_a);
        assert_eq!(sum.value(), &BigUint::from(0u32));
    }

    #[test]
    fn test_scalar_inverse() {
        let a = Scalar::new(BigUint::from(5u32));
        let a_inv = a.inverse();
        let product = a.mul(&a_inv);
        assert_eq!(product.value(), &BigUint::from(1u32));
    }

    #[test]
    fn test_scalar_from_bytes() {
        let bytes = [0x12, 0x34, 0x56, 0x78];
        let scalar = Scalar::from_bytes_be(&bytes);
        assert_eq!(scalar.to_bytes_be(), bytes);

        let scalar_le = Scalar::from_bytes_le(&bytes);
        assert_eq!(scalar_le.to_bytes_le(), bytes);
    }

    #[test]
    fn test_scalar_zero_and_one() {
        let zero = Scalar::zero();
        let one = Scalar::one();

        assert_eq!(zero.value(), &BigUint::from(0u32));
        assert_eq!(one.value(), &BigUint::from(1u32));

        // Test that 0 + 1 = 1
        assert_eq!(zero.add(&one), one);

        // Test that 1 * 1 = 1
        assert_eq!(one.mul(&one), one);

        // Test that 0 * x = 0 for some arbitrary x
        let x = Scalar::new(BigUint::from(123u32));
        assert_eq!(zero.mul(&x), zero);
    }
}
