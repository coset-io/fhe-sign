use std::ops::{Add, Mul};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyBigUint {
    // Represent the number as a vector of u32 digits, least significant digit first
    digits: Vec<u32>,
}

impl MyBigUint {
    /// Creates a new BigUint from a u32 value
    pub fn new(value: u32) -> Self {
        if value == 0 {
            Self { digits: vec![] }
        } else {
            Self { digits: vec![value] }
        }
    }

    /// Normalize the digits vector by removing trailing zeros
    fn normalize(&mut self) {
        while let Some(&last) = self.digits.last() {
            if last == 0 {
                self.digits.pop();
            } else {
                break;
            }
        }
    }

    /// Creates a BigUint from a vector of u32 digits
    pub fn from_digits(mut digits: Vec<u32>) -> Self {
        let mut result = Self { digits };
        result.normalize();
        result
    }

    /// Returns zero
    pub fn zero() -> Self {
        Self { digits: vec![] }
    }

    /// Returns one
    pub fn one() -> Self {
        Self { digits: vec![1] }
    }

    /// Converts the MyBigUint to a u32.
    /// Returns `Some(u32)` if it fits, otherwise `None`.
    pub fn to_u32(&self) -> Option<u32> {
        match self.digits.len() {
            0 => Some(0),                // Handle zero
            1 => self.digits.get(0).cloned(), // Single digit
            _ => None,                   // More than one digit may overflow
        }
    }

    /// Converts the MyBigUint to an i64.
    /// Returns `Some(i64)` if it fits, otherwise `None`.
    pub fn to_i64(&self) -> Option<i64> {
        match self.digits.len() {
            0 => Some(0),
            1 => self.digits.get(0).cloned().map(|d| d as i64),
            2 => {
                let low = self.digits.get(0).cloned().unwrap_or(0) as u64;
                let high = self.digits.get(1).cloned().unwrap_or(0) as u64;
                let combined = low | (high << 32);
                if combined <= i64::MAX as u64 {
                    Some(combined as i64)
                } else {
                    None
                }
            },
            _ => None,
        }
    }

    /// Converts the MyBigUint to a u64.
    /// Returns `Some(u64)` if it fits, otherwise `None`.
    pub fn to_u64(&self) -> Option<u64> {
        match self.digits.len() {
            0 => Some(0),
            1 => self.digits.get(0).cloned().map(|d| d as u64),
            2 => {
                let low = self.digits.get(0).cloned().unwrap_or(0) as u64;
                let high = self.digits.get(1).cloned().unwrap_or(0) as u64;
                Some(low | (high << 32))
            },
            _ => None,
        }
    }

    // Add other conversion methods as needed...
}

impl Add for MyBigUint {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut result = Vec::new();
        let mut carry = 0u32;
        let max_len = std::cmp::max(self.digits.len(), other.digits.len());

        for i in 0..max_len {
            let a = if i < self.digits.len() { self.digits[i] } else { 0 };
            let b = if i < other.digits.len() { other.digits[i] } else { 0 };
            let sum = (a as u64) + (b as u64) + (carry as u64);
            result.push(sum as u32);
            carry = (sum >> 32) as u32;
        }

        if carry > 0 {
            result.push(carry);
        }

        Self::from_digits(result)
    }
}

impl Mul for MyBigUint {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        if self.digits.is_empty() || other.digits.is_empty() {
            return Self::zero();
        }

        let mut result = vec![0u32; self.digits.len() + other.digits.len()];
        let mut total_carry = 0u32;

        for (i, &a) in self.digits.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in other.digits.iter().enumerate() {
                let idx = i + j;
                let product = (a as u64) * (b as u64) + (result[idx] as u64) + carry;
                result[idx] = product as u32;
                carry = product >> 32;
            }
            if carry > 0 {
                let idx = i + other.digits.len();
                let sum = (result[idx] as u64) + carry;
                result[idx] = sum as u32;
                total_carry = (sum >> 32) as u32;
                if total_carry > 0 && idx + 1 < result.len() {
                    result[idx + 1] += total_carry;
                }
            }
        }

        Self::from_digits(result)
    }
}

impl From<u32> for MyBigUint {
    fn from(value: u32) -> Self {
        MyBigUint::new(value)
    }
}

impl fmt::Display for MyBigUint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.digits.is_empty() {
            return write!(f, "0");
        }

        let mut result = String::new();
        let mut temp = self.clone();

        while !temp.digits.is_empty() {
            let mut remainder = 0u32;
            let mut new_digits = Vec::new();
            let mut leading_zero = true;

            for &digit in temp.digits.iter().rev() {
                let current = (remainder as u64) << 32 | digit as u64;
                let new_digit = (current / 10) as u32;
                remainder = (current % 10) as u32;

                if new_digit != 0 || !leading_zero {
                    new_digits.push(new_digit);
                    leading_zero = false;
                }
            }

            result.insert(0, char::from_digit(remainder, 10).unwrap());
            new_digits.reverse();
            temp.digits = new_digits;
        }

        write!(f, "{}", result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn test_add() {
        let a = MyBigUint::new(1);
        let b = MyBigUint::new(2);
        let result = a + b;
        assert_eq!(result.to_u32(), Some(3));
    }

    #[test]
    fn test_mul() {
        let a = MyBigUint::new(3);
        let b = MyBigUint::new(4);
        let result = a * b;
        assert_eq!(result.to_u32(), Some(12));
    }

    #[test]
    fn test_mul_zero() {
        let a = MyBigUint::from(0u32);
        let b = MyBigUint::from(12345u32);
        let result = a * b;
        assert_eq!(result.to_u32(), Some(0)); // Now correctly returns Some(0)
    }

    #[test]
    fn test_to_i64() {
        let a = MyBigUint::new(123456789u32);
        assert_eq!(a.to_i64(), Some(123456789));

        let large = MyBigUint::from_digits(vec![u32::MAX, u32::MAX]);
        assert_eq!(large.to_i64(), None); // Exceeds i64::MAX
    }

    #[test]
    fn test_to_u64() {
        let a = MyBigUint::new(123456789u32);
        assert_eq!(a.to_u64(), Some(123456789));

        let large = MyBigUint::from_digits(vec![u32::MAX, u32::MAX]);
        assert_eq!(large.to_u64(), Some(0xFFFFFFFF_FFFFFFFF)); // 18446744073709551615
    }

    #[test]
    fn test_large_add() {
        let a = MyBigUint::from_digits(vec![u32::MAX, u32::MAX, u32::MAX, u32::MAX]);
        let b = MyBigUint::from_digits(vec![1, 0, 0, 0, 0]);
        let result = a + b;
        let expected = MyBigUint::from_digits(vec![0, 0, 0, 0, 1]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_large_mul() {
        let a = MyBigUint::from_digits(vec![u32::MAX, u32::MAX, u32::MAX]);
        let b = MyBigUint::from_digits(vec![2, 1]);
        println!("a: {:?}", a);
        println!("b: {:?}", b);
        // print u64 format
        println!("a: {:?}", a.to_u64());
        println!("b: {:?}", b.to_u64());
        let result = a * b;
        println!("result: {:?}", result.to_string());
        // Compare with num-bigint library
        let a_bigint = BigUint::new(vec![u32::MAX, u32::MAX, u32::MAX]);
        let b_bigint = BigUint::new(vec![2, 1]);
        let result_bigint = a_bigint * b_bigint;
        println!("result_bigint: {:?}", result_bigint.to_string());
        let result_digits: Vec<u32> = result_bigint.to_u32_digits();
        let expected_bigint = MyBigUint::from_digits(result_digits);
        assert_eq!(result, expected_bigint);
    }

    #[test]
    fn test_large_add_overflow() {
        let a = MyBigUint::from_digits(vec![u32::MAX, u32::MAX]);
        let b = MyBigUint::from_digits(vec![1, 1]);
        let result = a + b;
        let a_bigint = BigUint::new(vec![u32::MAX, u32::MAX]);
        let b_bigint = BigUint::new(vec![1, 1]);
        let result_bigint = a_bigint + b_bigint;
        let result_digits: Vec<u32> = result_bigint.to_u32_digits();
        let expected_bigint = MyBigUint::from_digits(result_digits);
        assert_eq!(result, expected_bigint);
    }

    #[test]
    fn test_large_mul_zero() {
        let a = MyBigUint::from_digits(vec![u32::MAX, u32::MAX, u32::MAX]);
        let b = MyBigUint::from_digits(vec![0]);
        let result = a * b;
        let expected = MyBigUint::zero();
        assert_eq!(result, expected);
    }
}
