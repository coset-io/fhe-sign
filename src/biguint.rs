use std::ops::{Add, Mul};
use std::fmt;
use tfhe::prelude::*;
use tfhe::{FheUint32, FheUint64, ClientKey};
use num_bigint::BigUint;

#[derive(Clone)]
pub struct BigUintFHE {
    // Represent the number as a vector of encrypted u32 digits, least significant digit first
    digits: Vec<FheUint32>,
}

impl BigUintFHE {
    /// Creates a new BigUintFHE from a BigUint value
    pub fn new(value: BigUint, client_key: &ClientKey) -> Result<Self, Box<dyn std::error::Error>> {
        if value == BigUint::from(0u32) {
            Ok(Self { digits: vec![] })
        } else {
            // Convert BigUint to a vector of u32 digits
            let digits: Vec<u32> = value.to_u32_digits();

            // Encrypt each digit
            let encrypted_digits = digits.into_iter()
                .map(|d| FheUint32::try_encrypt(d, client_key))
                .collect::<Result<Vec<_>, _>>()?;

            Ok(Self { digits: encrypted_digits })
        }
    }

    /// Creates a new BigUintFHE from a u32 value
    pub fn from_u32(value: u32, client_key: &ClientKey) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new(BigUint::from(value), client_key)
    }

    /// Normalize the digits vector by removing trailing zeros
    fn normalize(&mut self) {
        // Note: We can't easily check for zeros in encrypted form
        // This would require decryption which we don't want to do during computation
        // So we'll keep all digits for now
    }

    /// Creates a BigUint from a vector of encrypted u32 digits
    pub fn from_encrypted_digits(digits: Vec<FheUint32>) -> Self {
        Self { digits }
    }

    /// Returns zero
    pub fn zero(_client_key: &ClientKey) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self { digits: Vec::<FheUint32>::new() })
    }

    /// Returns one
    pub fn one(client_key: &ClientKey) -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_u32(1, client_key)
    }

    /// Decrypts the BigUintFHE to a BigUint
    pub fn to_biguint(&self, client_key: &ClientKey) -> BigUint {
        if self.digits.is_empty() {
            return BigUint::from(0u32);
        }

        let mut result = BigUint::from(0u32);
        let mut base = BigUint::from(1u32);

        for digit in &self.digits {
            let decrypted: u32 = digit.decrypt(client_key);
            result += base.clone() * decrypted;
            base *= BigUint::from(0x100000000u64);
        }

        result
    }

    /// Decrypts the BigUintFHE to a u32 if possible
    pub fn decrypt_to_u32(&self, client_key: &ClientKey) -> Option<u32> {
        match self.digits.len() {
            0 => Some(0u32),
            1 => {
                let decrypted: u32 = self.digits[0].decrypt(client_key);
                Some(decrypted)
            },
            _ => None,
        }
    }

    /// Decrypts the BigUintFHE to a u64 if possible
    pub fn decrypt_to_u64(&self, client_key: &ClientKey) -> Option<u64> {
        match self.digits.len() {
            0 => Some(0u64),
            1 => {
                let decrypted: u32 = self.digits[0].decrypt(client_key);
                Some(decrypted as u64)
            },
            2 => {
                let low: u32 = self.digits[0].decrypt(client_key);
                let high: u32 = self.digits[1].decrypt(client_key);
                Some((low as u64) | ((high as u64) << 32))
            },
            _ => None,
        }
    }

    /// Extract carry from a sum
    fn extract_carry(sum: &FheUint64) -> FheUint32 {
        // Right shift by 32 bits to get the carry
        FheUint32::cast_from(sum >> 32u64)
    }

    /// Extract lower 32 bits from a sum
    fn extract_lower_bits(sum: &FheUint64) -> FheUint32 {
        // Use bitwise AND with mask 0xFFFFFFFF to get lower 32 bits
        FheUint32::cast_from(sum & 0xFFFFFFFFu64)
    }
}

impl Add for BigUintFHE {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut result = Vec::new();
        let max_len = std::cmp::max(self.digits.len(), other.digits.len());
        let mut carry: Option<FheUint32> = None;

        for i in 0..max_len {
            let a = if i < self.digits.len() { Some(&self.digits[i]) } else { None };
            let b = if i < other.digits.len() { Some(&other.digits[i]) } else { None };

            let sum = match (a, b, carry.as_ref()) {
                (Some(a), Some(b), Some(c)) => {
                    // Convert to u64 for the sum
                    let a64 = FheUint64::cast_from(a.clone());
                    let b64 = FheUint64::cast_from(b.clone());
                    let c64 = FheUint64::cast_from(c.clone());
                    let temp_sum = a64 + b64 + c64;

                    // Extract carry and result
                    let next_carry = FheUint32::cast_from(&temp_sum >> 32u64);
                    carry = Some(next_carry);
                    FheUint32::cast_from(&temp_sum & 0xFFFFFFFFu64)
                },
                (Some(a), Some(b), None) => {
                    let a64 = FheUint64::cast_from(a.clone());
                    let b64 = FheUint64::cast_from(b.clone());
                    let temp_sum = a64 + b64;

                    let next_carry = FheUint32::cast_from(&temp_sum >> 32u64);
                    carry = Some(next_carry);
                    FheUint32::cast_from(&temp_sum & 0xFFFFFFFFu64)
                },
                (Some(a), None, Some(c)) => {
                    let a64 = FheUint64::cast_from(a.clone());
                    let c64 = FheUint64::cast_from(c.clone());
                    let temp_sum = a64 + c64;

                    let next_carry = FheUint32::cast_from(&temp_sum >> 32u64);
                    carry = Some(next_carry);
                    FheUint32::cast_from(&temp_sum & 0xFFFFFFFFu64)
                },
                (Some(a), None, None) => {
                    a.clone()
                },
                (None, Some(b), Some(c)) => {
                    let b64 = FheUint64::cast_from(b.clone());
                    let c64 = FheUint64::cast_from(c.clone());
                    let temp_sum = b64 + c64;

                    let next_carry = FheUint32::cast_from(&temp_sum >> 32u64);
                    carry = Some(next_carry);
                    FheUint32::cast_from(&temp_sum & 0xFFFFFFFFu64)
                },
                (None, Some(b), None) => {
                    b.clone()
                },
                (None, None, Some(c)) => {
                    c.clone()
                },
                (None, None, None) => break,
            };
            result.push(sum);
        }

        if let Some(c) = carry {
            result.push(c);
        }

        Self { digits: result }
    }
}

impl Mul for BigUintFHE {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        if self.digits.is_empty() || other.digits.is_empty() {
            return Self { digits: Vec::new() };
        }

        let mut result = Vec::with_capacity(self.digits.len() + other.digits.len());

        // Compute each partial product and add to the appropriate position
        for (i, a) in self.digits.iter().enumerate() {
            for (j, b) in other.digits.iter().enumerate() {
                let idx = i + j;
                let a64 = FheUint64::cast_from(a.clone());
                let b64 = FheUint64::cast_from(b.clone());
                let product = a64 * b64;

                // Add product to the appropriate position
                if idx >= result.len() {
                    result.push(product);
                } else {
                    result[idx] = result[idx].clone() + product;
                }
            }
        }

        // Process carries after all products are computed
        let mut i = 0;
        while i < result.len() {
            let carry = &result[i] >> 32u64;
            result[i] = &result[i] & 0xFFFFFFFFu64;

            // If we have a carry, add it to the next position or create a new digit
            if i + 1 >= result.len() {
                result.push(carry);
            } else {
                result[i + 1] = result[i + 1].clone() + carry;
            }
            i += 1;
        }

        Self { digits: result.into_iter().map(|d| FheUint32::cast_from(d)).collect() }
    }
}

// Note: Display implementation would require decryption
impl fmt::Display for BigUintFHE {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<encrypted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::ConfigBuilder;
    use tfhe::prelude::FheDecrypt;

    #[test]
    fn test_biguint_conversion() -> Result<(), Box<dyn std::error::Error>> {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test with a large number that requires multiple u32 digits
        let large_num = BigUint::parse_bytes(b"123456789123456789", 10).unwrap();
        let encrypted = BigUintFHE::new(large_num.clone(), &client_key)?;
        let decrypted = encrypted.to_biguint(&client_key);
        assert_eq!(decrypted, large_num);
        Ok(())
    }

    #[test]
    fn test_add_with_carry() -> Result<(), Box<dyn std::error::Error>> {
        let a_biguint = BigUint::from(0xFFFFFFFFu32);
        let b_biguint = BigUint::from(1u32);
        let result_biguint = a_biguint + b_biguint;
        let low_biguint: u32 = result_biguint.to_u32_digits()[0];
        let high_biguint: u32 = result_biguint.to_u32_digits()[1];
        assert_eq!(result_biguint, BigUint::from(0x100000000u64));
        assert_eq!(low_biguint, 0);
        assert_eq!(high_biguint, 1);

        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        let a = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key)?;
        let b = BigUintFHE::from_u32(1u32, &client_key)?;
        let result = a + b;

        assert_eq!(result.digits.len(), 2);
        let low: u32 = result.digits[0].decrypt(&client_key);
        let high: u32 = result.digits[1].decrypt(&client_key);
        println!("low: {}", low);
        println!("high: {}", high);
        assert_eq!(low, 0);
        assert_eq!(high, 1);
        Ok(())
    }

    #[test]
    fn test_mul_with_carry() -> Result<(), Box<dyn std::error::Error>> {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test case 1: 0xFFFFFFFF * 2 = 0x1FFFFFFFE
        let a = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key)?;
        let b = BigUintFHE::from_u32(2u32, &client_key)?;
        let result = a * b;

        assert_eq!(result.digits.len(), 2);
        let low: u32 = result.digits[0].decrypt(&client_key);
        let high: u32 = result.digits[1].decrypt(&client_key);
        assert_eq!(low, 0xFFFFFFFEu32);
        assert_eq!(high, 1);

        // Test case 2: 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001
        let a = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key)?;
        let b = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key)?;
        let result = a * b;

        assert_eq!(result.digits.len(), 2);
        let low: u32 = result.digits[0].decrypt(&client_key);
        let high: u32 = result.digits[1].decrypt(&client_key);
        assert_eq!(low, 1);
        assert_eq!(high, 0xFFFFFFFEu32);

        Ok(())
    }

    #[test]
    fn test_add_multiple_carries() -> Result<(), Box<dyn std::error::Error>> {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        let a = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key)?;
        let b = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key)?;
        let result = a + b;

        assert_eq!(result.digits.len(), 2);
        let low: u32 = result.digits[0].decrypt(&client_key);
        let high: u32 = result.digits[1].decrypt(&client_key);
        assert_eq!(low, 0xFFFFFFFEu32);
        assert_eq!(high, 1);
        Ok(())
    }

    #[test]
    fn test_mul_multiple_carries() -> Result<(), Box<dyn std::error::Error>> {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test case: 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001
        let a = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key)?;
        let b = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key)?;
        let result = a * b;

        assert_eq!(result.digits.len(), 2);
        let low: u32 = result.digits[0].decrypt(&client_key);
        let high: u32 = result.digits[1].decrypt(&client_key);
        assert_eq!(low, 1);
        assert_eq!(high, 0xFFFFFFFEu32);

        Ok(())
    }

    #[test]
    fn test_large_number_operations() -> Result<(), Box<dyn std::error::Error>> {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test with large numbers
        let a = BigUint::parse_bytes(b"123456789123456789", 10).unwrap();
        let b = BigUint::parse_bytes(b"987654321987654321", 10).unwrap();

        let a_enc = BigUintFHE::new(a.clone(), &client_key)?;
        let b_enc = BigUintFHE::new(b.clone(), &client_key)?;

        // Test addition
        let sum = a_enc.clone() + b_enc.clone();
        assert_eq!(sum.to_biguint(&client_key), a.clone() + b.clone());

        // Test multiplication
        let product = a_enc * b_enc;
        assert_eq!(product.to_biguint(&client_key), a * b);

        Ok(())
    }

    #[test]
    fn test_extract_carry_and_lower_bits() -> Result<(), Box<dyn std::error::Error>> {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test case 1: Simple addition without carry
        let num1 = FheUint64::try_encrypt(5u64, &client_key)?;
        let num2 = FheUint64::try_encrypt(3u64, &client_key)?;
        let sum = num1 + num2;  // 8

        let carry = BigUintFHE::extract_carry(&sum);
        let lower = BigUintFHE::extract_lower_bits(&sum);

        assert_eq!(FheDecrypt::<u32>::decrypt(&carry, &client_key), 0u32);
        assert_eq!(FheDecrypt::<u32>::decrypt(&lower, &client_key), 8u32);

        // Test case 2: Addition with carry
        let max = FheUint64::try_encrypt(0xFFFFFFFFu64, &client_key)?;
        let one = FheUint64::try_encrypt(1u64, &client_key)?;
        let sum_with_carry = max + one;  // 0x100000000

        let carry = BigUintFHE::extract_carry(&sum_with_carry);
        let lower = BigUintFHE::extract_lower_bits(&sum_with_carry);

        assert_eq!(FheDecrypt::<u32>::decrypt(&carry, &client_key), 1u32);
        assert_eq!(FheDecrypt::<u32>::decrypt(&lower, &client_key), 0u32);

        // Test case 3: Large numbers
        let large1 = FheUint64::try_encrypt(0xFFFFFFFFu64, &client_key)?;
        let large2 = FheUint64::try_encrypt(0xFFFFFFFFu64, &client_key)?;
        let large_sum = large1 + large2;  // 0x1FFFFFFFE

        let carry = BigUintFHE::extract_carry(&large_sum);
        let lower = BigUintFHE::extract_lower_bits(&large_sum);

        assert_eq!(FheDecrypt::<u32>::decrypt(&carry, &client_key), 1u32);
        assert_eq!(FheDecrypt::<u32>::decrypt(&lower, &client_key), 0xFFFFFFFEu32);

        Ok(())
    }

    #[test]
    fn test_uint32_overflow_behavior() -> Result<(), Box<dyn std::error::Error>> {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test maximum u32 value plus one
        let max = FheUint32::try_encrypt(0xFFFFFFFFu32, &client_key)?;
        let one = FheUint32::try_encrypt(1u32, &client_key)?;
        let sum = &max + &one;

        // Extract carry and lower bits
        let carry = &sum >> 32u32;
        let lower = &sum & 0xFFFFFFFFu32;
        // TFHE does not support overflow checking, here the carry is 0, which should be 1 if computed in plaintext
        println!("carry: {}", FheDecrypt::<u32>::decrypt(&carry, &client_key));
        println!("lower: {}", FheDecrypt::<u32>::decrypt(&lower, &client_key));

        // Test maximum u32 value plus itself
        let sum2 = &max + &max;
        let carry2 = &sum2 >> 32u32;
        let lower2 = &sum2 & 0xFFFFFFFFu32;

        // TFHE does not support overflow checking, here the carry is 0, which should be 1 if computed in plaintext
        println!("carry2: {}", FheDecrypt::<u32>::decrypt(&carry2, &client_key));
        println!("lower2: {}", FheDecrypt::<u32>::decrypt(&lower2, &client_key));
        // Expected output(which is wrong because of overflow):
        // carry: 0
        // lower: 0
        // carry2: 4294967294
        // lower2: 4294967294
        Ok(())
    }

    #[test]
    fn test_uint64_carry_behavior() -> Result<(), Box<dyn std::error::Error>> {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test maximum u32 value plus one
        let max = FheUint64::try_encrypt(0xFFFFFFFFu64, &client_key)?;
        let one = FheUint64::try_encrypt(1u64, &client_key)?;
        let sum = &max + &one;

        // Extract carry and lower bits
        let carry = &sum >> 32u64;
        let lower = &sum & 0xFFFFFFFFu64;
        // TFHE does not support overflow checking, here the carry is 0, which should be 1 if computed in plaintext
        assert_eq!(FheDecrypt::<u64>::decrypt(&carry, &client_key), 1u64);
        assert_eq!(FheDecrypt::<u64>::decrypt(&lower, &client_key), 0u64);

        // Test maximum u32 value plus itself
        let sum2 = &max + &max;
        let carry2 = &sum2 >> 32u64;
        let lower2 = &sum2 & 0xFFFFFFFFu64;

        // TFHE does not support overflow checking, here the carry is 0, which should be 1 if computed in plaintext
        assert_eq!(FheDecrypt::<u64>::decrypt(&carry2, &client_key), 1u64);
        assert_eq!(FheDecrypt::<u64>::decrypt(&lower2, &client_key), 0xFFFFFFFEu64);
        Ok(())
    }
}

