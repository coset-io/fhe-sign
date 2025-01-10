use crate::scalar::Scalar;
use std::{clone::Clone, fmt::{Debug, Display}};

// implement secp256k1 elliptic curve: y^2 = x^3 + 7

// field size
// const P: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
const CURVE_ORDER: u32 = 65521;
// curve order: points number this curve can have
// const CURVE_ORDER: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

// elliptic curve point
pub struct Point {
    pub x: Scalar,  // should we use scalar?
    pub y: Scalar,
    pub is_infinity: bool,
}

impl Point {
    pub fn new(x: Scalar, y: Scalar, is_infinity: bool) -> Self {
        Self { x, y, is_infinity }
    }

    /// Creates a new point at infinity.
    pub fn infinity() -> Self {
        Self {
            x: Scalar::new(0, CURVE_ORDER),
            y: Scalar::new(0, CURVE_ORDER),
            is_infinity: true,
        }
    }

    /// Adds two points on the elliptic curve.
    pub fn add(&self, other: &Self) -> Self {
        // If either point is at infinity, return the other point
        if self.is_infinity {
            return other.clone();
        }
        if other.is_infinity {
            return self.clone();
        }

        // If the points have the same x coordinate
        if self.x == other.x {
            // If y coordinates are different, the result is infinity
            if self.y != other.y {
                return Self::infinity();
            } else {
                // Point doubling
                return self.double();
            }
        }

        // Calculate the slope (lambda)
        let numerator = &other.y - &self.y;
        let denominator = &other.x - &self.x;
        let lambda = numerator / denominator;

        // Calculate the new x coordinate
        let x3 = &lambda * &lambda - &self.x - &other.x;

        // Calculate the new y coordinate
        let y3 = &lambda * (&self.x - &x3) - &self.y;

        Self {
            x: x3,
            y: y3,
            is_infinity: false,
        }
    }

    /// Doubles a point on the elliptic curve.
    pub fn double(&self) -> Self {
        if self.is_infinity {
            return Self::infinity();
        }
        if self.y.value == 0 {
            return Self::infinity();
        }
        // Calculate the slope (lambda) for doubling
        let numerator = Scalar::new(3, CURVE_ORDER) * &self.x * &self.x;
        let denominator = Scalar::new(2, CURVE_ORDER) * &self.y;
        let lambda = numerator / denominator;

        // Calculate the new x coordinate
        let x3 = &lambda * &lambda - Scalar::new(2, CURVE_ORDER) * &self.x;

        // Calculate the new y coordinate
        let y3 = &lambda * (&self.x - &x3) - &self.y;

        Self {
            x: x3,
            y: y3,
            is_infinity: false,
        }
    }

    /// Multiplies a point by a scalar using the double-and-add algorithm.
    pub fn scalar_mul(&self, scalar: &Scalar) -> Self {
        let mut result = Self::infinity();
        let mut addend = self.clone();
        let mut k = scalar.value;

        while k > 0 {
            if k & 1 == 1 {
                result = result.add(&addend);
            }
            addend = addend.double();
            k >>= 1;
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
        let point_b = Point::new(Scalar::new(3, CURVE_ORDER), Scalar::new(4, CURVE_ORDER), false);

        // Adding point at infinity should return the other point
        assert_eq!(point_a.add(&point_b), point_b);
        assert_eq!(point_b.add(&point_a), point_b);
    }

    #[test]
    fn test_add_distinct_points() {
        let point_a = Point::new(Scalar::new(3, CURVE_ORDER), Scalar::new(4, CURVE_ORDER), false);
        let point_b = Point::new(Scalar::new(5, CURVE_ORDER), Scalar::new(6, CURVE_ORDER), false);

        // 计算斜率 lambda = (6 - 4) / (5 - 3) = 2 / 2 = 1
        let lambda = Scalar::new(1, CURVE_ORDER);

        // x3 = lambda^2 - x1 - x2 = 1 - 3 - 5 = -7 mod 65521 = 65514
        let expected_x = Scalar::new(-7, CURVE_ORDER);

        // y3 = lambda * (x1 - x3) - y1 = 1 * (3 - 65514) - 4 = 1 * (-65511) - 4 = -65515 mod 65521 = 6
        let expected_y = Scalar::new(-65515, CURVE_ORDER); // 65521 - (65515 mod 65521) = 6

        let result = point_a.add(&point_b);

        assert_eq!(result.x, expected_x);
        assert_eq!(result.y, expected_y);
        assert!(!result.is_infinity);
    }

    #[test]
    fn test_add_same_point() {
        let point_a = Point::new(Scalar::new(3, CURVE_ORDER), Scalar::new(4, CURVE_ORDER), false);

        // Compute doubling
        // lambda = (3x1^2 + a) / (2y1), assuming a = 0 for secp256k1
        // lambda = (3 * 3^2) / (2 * 4) = 27 / 8 = 3 (since 27 mod 65521 = 27, 8's inverse mod 65521 = 57331
        let numerator = Scalar::new(3, CURVE_ORDER) * &point_a.x * &point_a.x; // 3 * 3 * 3 = 27
        let denominator = Scalar::new(2, CURVE_ORDER) * &point_a.y; // 2 * 4 = 8
        let lambda = &numerator / &denominator; // 40954
        // For demonstration, let's choose lambda = 1 for simplicity
        println!("lambda: {}", lambda);
        println!("numerator: {}", numerator);
        println!("denominator: {}", denominator);
        println!("1 / denominator: {}", denominator.inverse());
        // x3 = lambda^2 - 2*x1 = 23552
        let expected_x = Scalar::new(23552, CURVE_ORDER); // 65521 - 5 = 65516

        // y3 = lambda * (x1 - x3) - y1 = 43370
        let expected_y = Scalar::new(43370, CURVE_ORDER); // 65521 - 65517 = 4

        let result = point_a.add(&point_a);

        assert_eq!(result.x, expected_x);
        assert_eq!(result.y, expected_y);
        assert!(!result.is_infinity);
    }

    #[test]
    fn test_add_opposite_points() {
        let point_a = Point::new(Scalar::new(3, CURVE_ORDER), Scalar::new(4, CURVE_ORDER), false);
        let point_b = Point::new(Scalar::new(3, CURVE_ORDER), Scalar::new(-4, CURVE_ORDER), false);

        // Adding a point and its opposite should result in the point at infinity
        assert_eq!(point_a.add(&point_b), Point::infinity());
    }
}
