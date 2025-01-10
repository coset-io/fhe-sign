use crate::field::FieldElement;
use crate::scalar::{Scalar, new_base_field, get_field_size};
use std::{clone::Clone, fmt::{Debug, Display}};
use num_bigint::BigUint;

/// Implementation of the secp256k1 elliptic curve: y^2 = x^3 + 7 (mod p)
/// The curve is defined over the prime field GF(p) where p is the field size.

// Curve parameters
const A: u32 = 0; // Coefficient of x term
const B: u32 = 7; // Constant term

/// A point on the secp256k1 curve.
/// Points are represented in affine coordinates (x, y).
/// The point at infinity is represented by a special flag.
#[derive(Clone, Debug, PartialEq)]
pub struct Point {
    pub x: FieldElement,
    pub y: FieldElement,
    pub is_infinity: bool,
}

impl Point {
    /// Creates a new point on the curve.
    /// Verifies that the point satisfies the curve equation y^2 = x^3 + 7 (mod p).
    pub fn new(x: FieldElement, y: FieldElement, is_infinity: bool) -> Self {
        if !is_infinity {
            // Verify that the point is on the curve
            let y2 = &y * &y;
            let x3 = &x * &x * &x;
            let rhs = x3 + new_base_field(BigUint::from(B));
            assert_eq!(y2, rhs, "Point is not on the curve");
        }
        Self { x, y, is_infinity }
    }

    /// Creates a new point at infinity (the identity element of the curve).
    pub fn infinity() -> Self {
        Self {
            x: new_base_field(BigUint::from(0u32)),
            y: new_base_field(BigUint::from(0u32)),
            is_infinity: true,
        }
    }

    /// Adds two points on the curve using the standard elliptic curve addition formulas.
    pub fn add(&self, other: &Point) -> Self {
        // Handle special cases involving point at infinity
        if self.is_infinity {
            return other.clone();
        }
        if other.is_infinity {
            return self.clone();
        }

        // If points are inverses of each other, return point at infinity
        if self.x == other.x {
            if self.y == other.y {
                // Point doubling case - handle it directly here
                let three = new_base_field(BigUint::from(3u32));
                let two = new_base_field(BigUint::from(2u32));
                let a = new_base_field(BigUint::from(A));

                let numerator = &(&three * &self.x * &self.x) + &a;
                let denominator = &two * &self.y;
                let lambda = &numerator / &denominator;

                // x3 = lambda^2 - 2x
                let x3 = &(&lambda * &lambda) - &(&two * &self.x);

                // y3 = lambda(x - x3) - y
                let y3 = &(&lambda * &(&self.x - &x3)) - &self.y;

                return Self::new(x3, y3, false);
            }
            if &self.y == &(-other.y.clone()) {
                return Self::infinity();
            }
        }

        // Different points addition: lambda = (y2 - y1) / (x2 - x1)
        let numerator = &other.y - &self.y;
        let denominator = &other.x - &self.x;
        let lambda = &numerator / &denominator;

        // Calculate new point coordinates
        // x3 = lambda^2 - x1 - x2
        let x3 = &(&lambda * &lambda) - &self.x - &other.x;

        // y3 = lambda(x1 - x3) - y1
        let y3 = &(&lambda * &(&self.x - &x3)) - &self.y;

        Self::new(x3, y3, false)
    }

    /// Doubles a point on the curve (adds it to itself).
    pub fn double(&self) -> Self {
        self.add(self)  // Now safe to use add since we handle doubling directly in add
    }

    /// Multiplies a point by a scalar using the double-and-add algorithm.
    /// This is an optimized version that avoids recursive calls and minimizes cloning.
    pub fn scalar_mul(&self, scalar: &Scalar) -> Self {
        if self.is_infinity {
            return Self::infinity();
        }

        let mut result = Self::infinity();
        let mut current = self.clone();
        let mut scalar_bits = scalar.value().clone();
        let zero = BigUint::from(0u32);
        let one = BigUint::from(1u32);

        // Double-and-add algorithm
        while scalar_bits > zero {
            if &scalar_bits & &one == one {
                result = result.add(&current);
            }
            current = current.double();
            scalar_bits >>= 1;
        }

        result
    }

    /// Returns the base point G of the secp256k1 curve.
    pub fn get_generator() -> Self {
        // Generator point coordinates from the secp256k1 specification
        let gx = FieldElement::new(
            BigUint::parse_bytes(b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap(),
            get_field_size()
        );
        let gy = FieldElement::new(
            BigUint::parse_bytes(b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).unwrap(),
            get_field_size()
        );
        Point::new(gx, gy, false) // Not a point at infinity
    }
}

impl Display for Point {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_infinity {
            write!(f, "Point at infinity")
        } else {
            write!(f, "({}, {})", self.x, self.y)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns the generator point of the secp256k1 curve
    fn get_generator() -> Point {
        let x = BigUint::parse_bytes(b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap();
        let y = BigUint::parse_bytes(b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).unwrap();
        
        Point::new(
            new_base_field(x),
            new_base_field(y),
            false
        )
    }

    #[test]
    fn test_generator_point() {
        let g = get_generator();
        
        // Verify that G is on the curve
        let y2 = &g.y * &g.y;
        let x3 = &g.x * &g.x * &g.x;
        let rhs = x3 + new_base_field(BigUint::from(B));
        assert_eq!(y2, rhs, "Generator point is not on the curve");
    }

    #[test]
    fn test_point_at_infinity() {
        let point = Point::infinity();
        assert!(point.is_infinity);
    }

    #[test]
    fn test_point_addition() {
        let g = get_generator();
        let g2 = g.double();
        
        // Verify G + G = 2G is on the curve
        let y2 = &g2.y * &g2.y;
        let x3 = &g2.x * &g2.x * &g2.x;
        let rhs = x3 + new_base_field(BigUint::from(B));
        assert_eq!(y2, rhs, "2G is not on the curve");
    }

    #[test]
    fn test_scalar_multiplication() {
        let g = get_generator();
        let scalar = Scalar::new(BigUint::from(2u32));
        let g2 = g.scalar_mul(&scalar);
        
        // Verify 2G is on the curve
        let y2 = &g2.y * &g2.y;
        let x3 = &g2.x * &g2.x * &g2.x;
        let rhs = x3 + new_base_field(BigUint::from(B));
        assert_eq!(y2, rhs, "2G is not on the curve");
        
        // Verify that scalar multiplication matches repeated addition
        let g2_add = g.add(&g);
        assert_eq!(g2, g2_add);
    }
}
