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
    pub fn from_digits(digits: Vec<u32>) -> Self {
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

        for (i, &a) in self.digits.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in other.digits.iter().enumerate() {
                let idx = i + j;
                let product = (a as u64) * (b as u64) + (result[idx] as u64) + carry;
                result[idx] = product as u32;
                carry = product >> 32;
            }

            // Propagate carry through remaining digits
            let mut k = i + other.digits.len();
            while carry > 0 && k < result.len() {
                let sum = (result[k] as u64) + carry;
                result[k] = sum as u32;
                carry = sum >> 32;
                k += 1;
            }

            // If there's still carry left, extend the vector
            if carry > 0 {
                result.push(carry as u32);
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
        assert_eq!(result.to_u32(), Some(0));
    }

    #[test]
    fn test_very_large_mul() {
        // Test 256-bit multiplication
        let a = MyBigUint::from_digits(vec![u32::MAX; 8]); // 256 bits
        let b = MyBigUint::from_digits(vec![2]);
        let result = a.clone() * b.clone();
        let result_str = result.to_string();
        println!("result_str: {:?}", result_str);

        let a_bigint = BigUint::from_slice(&a.digits);
        let b_bigint = BigUint::from_slice(&b.digits);
        let result_bigint = a_bigint * b_bigint;
        let result_str_expected = result_bigint.to_string();
        println!("result_str_expected: {:?}", result_str_expected);
        assert_eq!(result_str, result_str_expected);

        let result_digits: Vec<u32> = result_bigint.to_u32_digits();
        let expected = MyBigUint::from_digits(result_digits);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_very_large_add() {
        // Test 256-bit addition
        let a = MyBigUint::from_digits(vec![u32::MAX; 8]); // 256 bits
        let b = MyBigUint::from_digits(vec![1]);
        let result = a.clone() + b.clone();
        let result_str = result.to_string();
        println!("result_str: {:?}", result_str);

        let a_bigint = BigUint::from_slice(&a.digits);
        let b_bigint = BigUint::from_slice(&b.digits);
        let result_bigint = a_bigint + b_bigint;
        let result_str_expected = result_bigint.to_string();
        println!("result_str_expected: {:?}", result_str_expected);
        assert_eq!(result_str, result_str_expected);

        let result_digits: Vec<u32> = result_bigint.to_u32_digits();
        let expected = MyBigUint::from_digits(result_digits);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_multiplication_carry_propagation() {
        // Create a number that will generate multiple carries
        let a = MyBigUint::from_digits(vec![u32::MAX, u32::MAX, u32::MAX]);
        let b = MyBigUint::from_digits(vec![u32::MAX, u32::MAX]);
        let result = a.clone() * b.clone();
        let result_str = result.to_string();
        println!("result_str: {:?}", result_str);

        let a_bigint = BigUint::from_slice(&a.digits);
        let b_bigint = BigUint::from_slice(&b.digits);
        let result_bigint = a_bigint * b_bigint;
        let result_str_expected = result_bigint.to_string();
        println!("result_str_expected: {:?}", result_str_expected);
        assert_eq!(result_str, result_str_expected);

        let result_digits: Vec<u32> = result_bigint.to_u32_digits();
        let expected = MyBigUint::from_digits(result_digits);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_normalize_large_numbers() {
        // Test that normalization works correctly with large numbers
        let mut num = MyBigUint::from_digits(vec![1, 0, 0, 0, 0, 0, 0, 0, 0]);
        num.normalize();
        assert_eq!(num.digits, vec![1]);
    }
}
