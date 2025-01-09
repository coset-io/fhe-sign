use std::ops::{Add, Mul};

use sha2::{Sha256, Digest};
use rand::Rng;


pub fn hash(r: u32, pk: u32, message: &str) -> u32 {
    let mut hasher_input = Vec::new();
    hasher_input.extend(&r.to_be_bytes());
    hasher_input.extend(&pk.to_be_bytes());
    hasher_input.extend(message.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&hasher_input);
    let hash_result = hasher.finalize();
    let result_u32 = u32::from_be_bytes(hash_result[..4].try_into().expect("Hash output too short"));
    result_u32 as u32
}

// implement scalar for elliptic curve group
pub struct Scalar{
    value: u32,
    order: u32, // group order
}

impl Scalar {
    pub fn new(value: u32, order: u32) -> Self {
        // value should modulo g
        Self { value: value % order, order }
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self { value: (self.value + other.value) % self.order, order: self.order }
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        Self { value: (self.value * other.value) % self.order, order: self.order }
    }
}

pub struct Schnorr {
    private_key: u32,
    public_key: u32,
    g: u32,
}

impl Schnorr {
    pub fn new(private_key: u32) -> Self {
        let g: u32 = 2; // Define G
        let public_key = private_key * g;
        Self { private_key, public_key, g }
    }

    pub fn sign(&self, message: &str) -> (u32, u64) {
        // 1. generate a random number k
        // let k = rand::thread_rng().gen_range(0..=255);
        let k = 100;
        // 2. calculate r = k * G
        let r = k * self.g;
        // 3. calculate public key pk = private_key * G
        let pk = self.private_key * self.g;
        // 4. calculate e = hash(r || pk || message)
        let e = hash(r, pk, message);
        println!("e: {}", e);
        // 5. calculate s = k + e * private_key
        let s = k as u64 + (e as u64) * self.private_key as u64;
        // 6. return signature (r, s)
        (r, s)
    }

    pub fn verify(&self, message: &str, signature: (u32, u64)) -> bool {
        // 1. get the signature
        let (r, s) = signature;
        // 2. get the public key
        let pk = self.public_key;
        // 3. calculate e = hash(r || pk || message)
        let e = hash(r, pk, message);
        // 4. verify the signature: s * G = r + e * pk
        assert_eq!(s * self.g as u64, r as u64 + (e as u64) * pk as u64);
        true
    }
}

// add test
#[cfg(test)]
mod tests {
    use tfhe::integer::bigint::u256;

    use super::*;

    #[test]
    fn test_schnorr() {
        let schnorr = Schnorr::new(1);
        let signature = schnorr.sign("hello");
        assert!(schnorr.verify("hello", signature));
    }

    // Start Generation Here
    #[test]
    fn test_scalar_new() {
        let g = 5;
        let scalar = Scalar::new(10, g);
        assert_eq!(scalar.value, 0); // 10 % 5 = 0
        assert_eq!(scalar.order, g);
    }

    #[test]
    fn test_scalar_addition() {
        let g = 5;
        let a = Scalar::new(2, g);
        let b = Scalar::new(3, g);
        let c = a + b;
        assert_eq!(c.value, 0); // (2 + 3) % 5 = 0
        assert_eq!(c.order, g);
    }

    #[test]
    fn test_scalar_multiplication() {
        let g = 7;
        let a = Scalar::new(3, g);
        let b = Scalar::new(4, g);
        let c = a * b;
        assert_eq!(c.value, 5); // (3 * 4) % 7 = 5
        assert_eq!(c.order, g);
    }

    // #[test]
    // fn test_scalar_order() {
    //     // Order of the secp256k1 elliptic curve in hexadecimal
    //     const ORDER_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    //     let order = u256::from(ORDER_HEX.split_at(32));
    //     println!("{:?}", order);
    // }
}


