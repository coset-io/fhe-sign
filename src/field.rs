use std::{clone::Clone, fmt::{Debug, Display}, ops::{Add, Div, Mul, Neg, Sub}};
use num_bigint::{BigUint, BigInt};

/// Represents an element in a prime field GF(p).
/// All operations are performed modulo the field characteristic p.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldElement {
    value: BigUint,
    order: BigUint,
}

impl FieldElement {
    /// Creates a new field element with the given value and order.
    /// The value is automatically reduced modulo the order.
    pub fn new(value: BigUint, order: BigUint) -> Self {
        let reduced_value = value % &order;
        Self { value: reduced_value, order }
    }

    /// Returns the value of the field element.
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Returns the order of the field.
    pub fn order(&self) -> &BigUint {
        &self.order
    }

    /// Computes the multiplicative inverse using the Extended Euclidean Algorithm.
    pub fn inverse(&self) -> Self {
        if self.value == BigUint::from(0u32) {
            panic!("Cannot compute multiplicative inverse of zero");
        }

        let mut t = BigInt::from(0);
        let mut newt = BigInt::from(1);
        let mut r = BigInt::from(self.order.clone());
        let mut newr = BigInt::from(self.value.clone());

        while newr != BigInt::from(0) {
            let quotient = &r / &newr;
            let t_next = newt.clone();
            let r_next = newr.clone();
            newt = t - &quotient * &newt;
            newr = r - &quotient * &newr;
            t = t_next;
            r = r_next;
        }

        if r > BigInt::from(1) {
            panic!("Value and field order are not coprime");
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

        Self {
            value,
            order: self.order.clone(),
        }
    }
}

impl Add for FieldElement {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        assert_eq!(self.order, other.order, "Cannot add elements from different fields");
        Self {
            value: (self.value + other.value) % &self.order,
            order: self.order,
        }
    }
}

impl<'a> Add<&'a FieldElement> for FieldElement {
    type Output = Self;

    fn add(self, other: &'a FieldElement) -> Self::Output {
        assert_eq!(self.order, other.order, "Cannot add elements from different fields");
        Self {
            value: (self.value + &other.value) % &self.order,
            order: self.order,
        }
    }
}

impl<'a> Add<&'a FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn add(self, other: &'a FieldElement) -> Self::Output {
        assert_eq!(self.order, other.order, "Cannot add elements from different fields");
        FieldElement {
            value: (&self.value + &other.value) % &self.order,
            order: self.order.clone(),
        }
    }
}

impl Neg for FieldElement {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            value: if self.value == BigUint::from(0u32) {
                BigUint::from(0u32)
            } else {
                &self.order - &self.value
            },
            order: self.order,
        }
    }
}

impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        assert_eq!(self.order, other.order, "Cannot subtract elements from different fields");
        let mut result = self.value;
        if result < other.value {
            result = result + &self.order;
        }
        Self {
            value: (result - other.value) % &self.order,
            order: self.order,
        }
    }
}

impl<'a> Sub<&'a FieldElement> for FieldElement {
    type Output = Self;

    fn sub(self, other: &'a FieldElement) -> Self::Output {
        assert_eq!(self.order, other.order, "Cannot subtract elements from different fields");
        let mut result = self.value;
        if result < other.value {
            result = result + &self.order;
        }
        Self {
            value: (result - &other.value) % &self.order,
            order: self.order,
        }
    }
}

impl<'a> Sub<&'a FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &'a FieldElement) -> Self::Output {
        assert_eq!(self.order, other.order, "Cannot subtract elements from different fields");
        let mut result = self.value.clone();
        if result < other.value {
            result = result + &self.order;
        }
        FieldElement {
            value: (result - &other.value) % &self.order,
            order: self.order.clone(),
        }
    }
}

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        assert_eq!(self.order, other.order, "Cannot multiply elements from different fields");
        Self {
            value: (self.value * other.value) % &self.order,
            order: self.order,
        }
    }
}

impl<'a> Mul<&'a FieldElement> for FieldElement {
    type Output = Self;

    fn mul(self, other: &'a FieldElement) -> Self::Output {
        assert_eq!(self.order, other.order, "Cannot multiply elements from different fields");
        Self {
            value: (self.value * &other.value) % &self.order,
            order: self.order,
        }
    }
}

impl<'a> Mul<&'a FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &'a FieldElement) -> Self::Output {
        assert_eq!(self.order, other.order, "Cannot multiply elements from different fields");
        FieldElement {
            value: (&self.value * &other.value) % &self.order,
            order: self.order.clone(),
        }
    }
}

impl Div for FieldElement {
    type Output = Self;

    fn div(self, other: Self) -> Self::Output {
        assert_eq!(self.order, other.order, "Cannot divide elements from different fields");
        if other.value == BigUint::from(0u32) {
            panic!("Division by zero");
        }
        self * other.inverse()
    }
}

impl<'a> Div<&'a FieldElement> for FieldElement {
    type Output = Self;

    fn div(self, other: &'a FieldElement) -> Self::Output {
        assert_eq!(self.order, other.order, "Cannot divide elements from different fields");
        if other.value == BigUint::from(0u32) {
            panic!("Division by zero");
        }
        self * other.inverse()
    }
}

impl<'a> Div<&'a FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn div(self, other: &'a FieldElement) -> Self::Output {
        assert_eq!(self.order, other.order, "Cannot divide elements from different fields");
        if other.value == BigUint::from(0u32) {
            panic!("Division by zero");
        }
        self * &other.inverse()
    }
}

impl Display for FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_element_creation() {
        let order = BigUint::from(17u32);
        let value = BigUint::from(20u32);
        let element = FieldElement::new(value, order.clone());
        assert_eq!(element.value, BigUint::from(3u32));
        assert_eq!(element.order, order);
    }

    #[test]
    fn test_field_element_addition() {
        let order = BigUint::from(17u32);
        let a = FieldElement::new(BigUint::from(15u32), order.clone());
        let b = FieldElement::new(BigUint::from(5u32), order.clone());
        let sum = &a + &b;
        assert_eq!(sum.value, BigUint::from(3u32));
    }

    #[test]
    fn test_field_element_subtraction() {
        let order = BigUint::from(17u32);
        let a = FieldElement::new(BigUint::from(5u32), order.clone());
        let b = FieldElement::new(BigUint::from(10u32), order.clone());
        let diff = &a - &b;
        assert_eq!(diff.value, BigUint::from(12u32));
    }

    #[test]
    fn test_field_element_multiplication() {
        let order = BigUint::from(17u32);
        let a = FieldElement::new(BigUint::from(5u32), order.clone());
        let b = FieldElement::new(BigUint::from(10u32), order.clone());
        let product = &a * &b;
        assert_eq!(product.value, BigUint::from(16u32));
    }

    #[test]
    fn test_field_element_division() {
        let order = BigUint::from(17u32);
        let a = FieldElement::new(BigUint::from(5u32), order.clone());
        let b = FieldElement::new(BigUint::from(10u32), order.clone());
        let quotient = &a / &b;
        let product = &quotient * &b;
        assert_eq!(product.value, a.value);
    }

    #[test]
    fn test_field_element_inverse() {
        let order = BigUint::from(17u32);
        let a = FieldElement::new(BigUint::from(5u32), order.clone());
        let a_inv = a.inverse();
        let product = &a * &a_inv;
        assert_eq!(product.value, BigUint::from(1u32));
    }
}