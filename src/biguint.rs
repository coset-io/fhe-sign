use std::ops::{Add, Mul};
use std::fmt;
use tfhe::prelude::*;
use tfhe::{FheUint32, FheUint64, ClientKey};
use num_bigint::BigUint;
use std::time::Instant;

#[derive(Clone)]
pub struct BigUintFHE {
    // Represent the number as a vector of encrypted u32 digits, least significant digit first
    digits: Vec<FheUint32>,
    client_key: ClientKey,
}

impl BigUintFHE {
    /// Creates a new BigUintFHE from a BigUint value
    pub fn new(value: BigUint, client_key: &ClientKey) -> Result<Self, tfhe::Error> {
        if value == BigUint::from(0u32) {
            Ok(Self { digits: vec![], client_key: client_key.clone() })
        } else {
            // Convert BigUint to a vector of u32 digits
            let digits: Vec<u32> = value.to_u32_digits();

            // Encrypt each digit
            let encrypted_digits = digits.into_iter()
                .map(|d| FheUint32::try_encrypt(d, client_key))
                .collect::<Result<Vec<_>, _>>()?;

            Ok(Self { digits: encrypted_digits, client_key: client_key.clone() })
        }
    }

    /// Creates a new BigUintFHE from a u32 value
    pub fn from_u32(value: u32, client_key: &ClientKey) -> Result<Self, tfhe::Error> {
        Self::new(BigUint::from(value), client_key)
    }

    /// Normalize the digits vector by removing trailing zeros
    fn normalize(&mut self) {
        // Note: We can't easily check for zeros in encrypted form
        // This would require decryption which we don't want to do during computation
        // So we'll keep all digits for now
    }

    /// Creates a BigUint from a vector of encrypted u32 digits
    pub fn from_encrypted_digits(digits: Vec<FheUint32>, client_key: &ClientKey) -> Self {
        Self { digits, client_key: client_key.clone() }
    }

    /// Returns zero
    pub fn zero(client_key: &ClientKey) -> Result<Self, tfhe::Error> {
        Ok(Self { digits: Vec::<FheUint32>::new(), client_key: client_key.clone() })
    }

    /// Returns one
    pub fn one(client_key: &ClientKey) -> Result<Self, tfhe::Error> {
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

        Self { digits: result, client_key: self.client_key.clone() }
    }
}

impl Mul for BigUintFHE {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        if self.digits.is_empty() || other.digits.len() == 0 {
            return Self { digits: Vec::new(), client_key: self.client_key.clone() };
        }

        let start_total = Instant::now();

        // Initialize result vector with zeros
        let start_init = Instant::now();
        let mut result = vec![
            FheUint32::try_encrypt(0u32, &self.client_key).unwrap();
            self.digits.len() + other.digits.len()
        ];
        println!("Init time: {:?}", start_init.elapsed());

        // Compute each partial product and add to the appropriate position
        let start_products = Instant::now();
        for (i, a) in self.digits.iter().enumerate() {
            for (j, b) in other.digits.iter().enumerate() {
                let start_iter = Instant::now();
                let idx = i + j;

                let start_decrypt = Instant::now();
                let a32_clear: u32 = a.decrypt(&self.client_key);
                let b32_clear: u32 = b.decrypt(&self.client_key);
                let product_clear = a32_clear as u64 * b32_clear as u64;
                println!("Decrypt time: {:?}", start_decrypt.elapsed());

                // Split product into lower and upper 32 bits
                let start_encrypt = Instant::now();
                let lower = FheUint32::try_encrypt((product_clear & 0xFFFFFFFF) as u32, &self.client_key).unwrap();
                let upper = FheUint32::try_encrypt((product_clear >> 32) as u32, &self.client_key).unwrap();
                println!("Encrypt time: {:?}", start_encrypt.elapsed());

                let start_add = Instant::now();
                // Add lower part and handle potential carry
                let current_pos = FheUint64::cast_from(result[idx].clone());
                let lower64 = FheUint64::cast_from(lower);
                let sum = current_pos + lower64;
                result[idx] = BigUintFHE::extract_lower_bits(&sum);

                // Add upper part plus any carry from lower addition
                let next_pos = FheUint64::cast_from(result[idx + 1].clone());
                let upper64 = FheUint64::cast_from(upper);
                let carry64 = FheUint64::cast_from(BigUintFHE::extract_carry(&sum));
                let sum = next_pos + upper64 + carry64;
                result[idx + 1] = BigUintFHE::extract_lower_bits(&sum);

                // Handle potential new carry
                if idx + 2 < result.len() {
                    result[idx + 2] = result[idx + 2].clone() + BigUintFHE::extract_carry(&sum);
                }
                println!("Addition time: {:?}", start_add.elapsed());

                println!("Total iteration time: {:?}", start_iter.elapsed());
            }
        }
        println!("Total products time: {:?}", start_products.elapsed());

        let result = Self {
            digits: result,
            client_key: self.client_key.clone()
        };

        println!("Total multiplication time: {:?}", start_total.elapsed());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::ConfigBuilder;
    use tfhe::prelude::FheDecrypt;

    #[test]
    fn test_mul_with_carry_small_numbers() {
        println!("starting test");
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        println!("finished generating keys");
        // Use small numbers for initial testing
        let a = BigUintFHE::from_u32(2u32, &client_key).unwrap();
        println!("finished from_u32 a");
        let b = BigUintFHE::from_u32(3u32, &client_key).unwrap();
        println!("finished from_u32 b");
        let result = a * b;
        println!("finished mul");

        // Decrypt the result to verify correctness
        let decrypted = result.to_biguint(&client_key);
        assert_eq!(decrypted, BigUint::from(6u32));
    }

    #[test]
    fn test_biguint_conversion() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test with a large number that requires multiple u32 digits
        let large_num = BigUint::parse_bytes(b"123456789123456789", 10).unwrap();
        let encrypted = BigUintFHE::new(large_num.clone(), &client_key).unwrap();
        let decrypted = encrypted.to_biguint(&client_key);
        assert_eq!(decrypted, large_num);
    }

    #[test]
    fn test_add_with_carry() {
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

        let a = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key).unwrap();
        let b = BigUintFHE::from_u32(1u32, &client_key).unwrap();
        let result = a + b;

        assert_eq!(result.digits.len(), 2);
        let low: u32 = result.digits[0].decrypt(&client_key);
        let high: u32 = result.digits[1].decrypt(&client_key);
        println!("low: {}", low);
        println!("high: {}", high);
        assert_eq!(low, 0);
        assert_eq!(high, 1);
    }

    #[test]
    fn test_mul_with_carry() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test case 1: 0xFFFFFFFF * 2 = 0x1FFFFFFFE
        let a = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key).unwrap();
        let b = BigUintFHE::from_u32(2u32, &client_key).unwrap();
        let result = a * b;

        assert_eq!(result.digits.len(), 2);
        let low: u32 = result.digits[0].decrypt(&client_key);
        let high: u32 = result.digits[1].decrypt(&client_key);
        assert_eq!(low, 0xFFFFFFFEu32);
        assert_eq!(high, 1);
    }

    #[test]
    fn test_mul_with_carry_2() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test case 2: 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001
        let a = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key).unwrap();
        let b = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key).unwrap();
        let result = a * b;

        assert_eq!(result.digits.len(), 2);
        let low: u32 = result.digits[0].decrypt(&client_key);
        let high: u32 = result.digits[1].decrypt(&client_key);
        assert_eq!(low, 1);
        assert_eq!(high, 0xFFFFFFFEu32);
    }

    #[test]
    fn test_add_multiple_carries() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        let a = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key).unwrap();
        let b = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key).unwrap();
        let result = a + b;

        assert_eq!(result.digits.len(), 2);
        let low: u32 = result.digits[0].decrypt(&client_key);
        let high: u32 = result.digits[1].decrypt(&client_key);
        assert_eq!(low, 0xFFFFFFFEu32);
        assert_eq!(high, 1);
    }

    #[test]
    fn test_mul_multiple_carries() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test case: 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001
        let a = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key).unwrap();
        let b = BigUintFHE::from_u32(0xFFFFFFFFu32, &client_key).unwrap();
        let result = a * b;

        assert_eq!(result.digits.len(), 2);
        let low: u32 = result.digits[0].decrypt(&client_key);
        let high: u32 = result.digits[1].decrypt(&client_key);
        assert_eq!(low, 1);
        assert_eq!(high, 0xFFFFFFFEu32);
    }

    #[test]
    fn test_large_number_operations() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test with large numbers
        let a = BigUint::parse_bytes(b"123456789123456789", 10).unwrap();
        let b = BigUint::parse_bytes(b"987654321987654321", 10).unwrap();

        let a_enc = BigUintFHE::new(a.clone(), &client_key).unwrap();
        let b_enc = BigUintFHE::new(b.clone(), &client_key).unwrap();

        // Test addition
        let sum = a_enc.clone() + b_enc.clone();
        assert_eq!(sum.to_biguint(&client_key), a.clone() + b.clone());

        // Test multiplication
        let product = a_enc * b_enc;
        assert_eq!(product.to_biguint(&client_key), a * b);
    }

    #[test]
    fn test_extract_carry_and_lower_bits() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test case 1: Simple addition without carry
        let num1 = FheUint64::try_encrypt(5u64, &client_key).unwrap();
        let num2 = FheUint64::try_encrypt(3u64, &client_key).unwrap();
        let sum = num1 + num2;  // 8

        let carry = BigUintFHE::extract_carry(&sum);
        let lower = BigUintFHE::extract_lower_bits(&sum);

        assert_eq!(FheDecrypt::<u32>::decrypt(&carry, &client_key), 0u32);
        assert_eq!(FheDecrypt::<u32>::decrypt(&lower, &client_key), 8u32);

        // Test case 2: Addition with carry
        let max = FheUint64::try_encrypt(0xFFFFFFFFu64, &client_key).unwrap();
        let one = FheUint64::try_encrypt(1u64, &client_key).unwrap();
        let sum_with_carry = max + one;  // 0x100000000

        let carry = BigUintFHE::extract_carry(&sum_with_carry);
        let lower = BigUintFHE::extract_lower_bits(&sum_with_carry);

        assert_eq!(FheDecrypt::<u32>::decrypt(&carry, &client_key), 1u32);
        assert_eq!(FheDecrypt::<u32>::decrypt(&lower, &client_key), 0u32);

        // Test case 3: Large numbers
        let large1 = FheUint64::try_encrypt(0xFFFFFFFFu64, &client_key).unwrap();
        let large2 = FheUint64::try_encrypt(0xFFFFFFFFu64, &client_key).unwrap();
        let large_sum = large1 + large2;  // 0x1FFFFFFFE

        let carry = BigUintFHE::extract_carry(&large_sum);
        let lower = BigUintFHE::extract_lower_bits(&large_sum);

        assert_eq!(FheDecrypt::<u32>::decrypt(&carry, &client_key), 1u32);
        assert_eq!(FheDecrypt::<u32>::decrypt(&lower, &client_key), 0xFFFFFFFEu32);
    }

    #[test]
    fn test_uint32_overflow_behavior() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test maximum u32 value plus one
        let max = FheUint32::try_encrypt(0xFFFFFFFFu32, &client_key).unwrap();
        let one = FheUint32::try_encrypt(1u32, &client_key).unwrap();
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
    }

    #[test]
    fn test_uint64_carry_behavior() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        tfhe::set_server_key(server_key);

        // Test maximum u32 value plus one
        let max = FheUint64::try_encrypt(0xFFFFFFFFu64, &client_key).unwrap();
        let one = FheUint64::try_encrypt(1u64, &client_key).unwrap();
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
    }

}

