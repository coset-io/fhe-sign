use crate::scalar::Scalar;
use std::{clone::Clone, fmt::{Debug, Display}};
use num_bigint::BigUint;

// Implementation of the secp256k1 elliptic curve: y^2 = x^3 + 7

// Field size (p) of secp256k1
const P: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";

// Curve parameters
const A: u32 = 0; // Coefficient of x term
const B: u32 = 7; // Constant term

// Elliptic curve point
pub struct Point {
    pub x: Scalar,
    pub y: Scalar,
    pub is_infinity: bool,
}

impl Point {
    pub fn new(x: Scalar, y: Scalar, is_infinity: bool) -> Self {
        Self { x, y, is_infinity }
    }

    /// Creates a new point at infinity (the identity element of the curve).
    pub fn infinity() -> Self {
        Self {
            x: Scalar::new(BigUint::from(0u32)),
            y: Scalar::new(BigUint::from(0u32)),
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
        if self.x == other.x && self.y == (-other.y.clone()) {
            return Self::infinity();
        }

        // Calculate slope (lambda)
        let lambda = if self.x == other.x && self.y == other.y {
            // Point doubling: lambda = (3x^2 + a) / (2y)
            let numerator = &(&Scalar::new(BigUint::from(3u32)) * &self.x * &self.x)
                + &Scalar::new(BigUint::from(A));
            let denominator = &Scalar::new(BigUint::from(2u32)) * &self.y;
            &numerator / &denominator
        } else {
            // Point addition: lambda = (y2 - y1) / (x2 - x1)
            let numerator = &other.y - &self.y;
            let denominator = &other.x - &self.x;
            &numerator / &denominator
        };

        // Calculate new point coordinates
        // x3 = lambda^2 - x1 - x2
        let x3 = &(&lambda * &lambda) - &self.x - &other.x;

        // y3 = lambda(x1 - x3) - y1
        let y3 = &(&lambda * &(&self.x - &x3)) - &self.y;

        Self::new(x3, y3, false)
    }

    /// Doubles a point on the curve (adds it to itself).
    pub fn double(&self) -> Self {
        self.add(self)
    }

    /// Multiplies a point by a scalar using the double-and-add algorithm.
    pub fn scalar_mul(&self, scalar: &Scalar) -> Self {
        let mut result = Self::infinity();
        let mut temp = self.clone();
        let mut scalar_bits = scalar.value.clone();

        while scalar_bits > BigUint::from(0u32) {
            if &scalar_bits & BigUint::from(1u32) == BigUint::from(1u32) {
                result = result.add(&temp);
            }
            temp = temp.double();
            scalar_bits >>= 1;
        }

        result
    }
}

impl Clone for Point {
    fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
            is_infinity: self.is_infinity,
        }
    }
}

impl Debug for Point {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Point {{ x: {}, y: {}, is_infinity: {} }}", self.x, self.y, self.is_infinity)
    }
}

impl Display for Point {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Point {{ x: {}, y: {}, is_infinity: {} }}", self.x, self.y, self.is_infinity)
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        self.x == other.x && self.y == other.y && self.is_infinity == other.is_infinity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_points_at_infinity() {
        let point_a = Point::infinity();
        let point_b = Point::new(
            Scalar::new(BigUint::from(3u32)),
            Scalar::new(BigUint::from(4u32)),
            false
        );

        // Adding point at infinity should return the other point
        assert_eq!(point_a.add(&point_b), point_b);
        assert_eq!(point_b.add(&point_a), point_b);
    }

    #[test]
    fn test_add_distinct_points() {
        let point_a = Point::new(
            Scalar::new(BigUint::from(3u32)),
            Scalar::new(BigUint::from(4u32)),
            false
        );
        let point_b = Point::new(
            Scalar::new(BigUint::from(5u32)),
            Scalar::new(BigUint::from(6u32)),
            false
        );

        let result = point_a.add(&point_b);

        // Verify result is on the curve: y^2 = x^3 + 7
        let x3_cubed = &result.x * &result.x * &result.x;
        let y2 = &result.y * &result.y;
        let right_side = &x3_cubed + &Scalar::new(BigUint::from(B));

        assert_eq!(y2, right_side);
    }

    #[test]
    fn test_point_doubling() {
        let point = Point::new(
            Scalar::new(BigUint::from(3u32)),
            Scalar::new(BigUint::from(4u32)),
            false
        );

        let doubled = point.double();

        // Verify result is on the curve: y^2 = x^3 + 7
        let x3_cubed = &doubled.x * &doubled.x * &doubled.x;
        let y2 = &doubled.y * &doubled.y;
        let right_side = &x3_cubed + &Scalar::new(BigUint::from(B));

        assert_eq!(y2, right_side);
    }

    #[test]
    fn test_scalar_multiplication() {
        let point = Point::new(
            Scalar::new(BigUint::from(3u32)),
            Scalar::new(BigUint::from(4u32)),
            false
        );
        let scalar = Scalar::new(BigUint::from(2u32));

        let result = point.scalar_mul(&scalar);

        // Verify result is on the curve: y^2 = x^3 + 7
        let x3_cubed = &result.x * &result.x * &result.x;
        let y2 = &result.y * &result.y;
        let right_side = &x3_cubed + &Scalar::new(BigUint::from(B));

        assert_eq!(y2, right_side);
    }
}
