use sha2::{Sha256, Digest};
use rand::Rng;
use crate::scalar::Scalar;
use num_bigint::BigUint;

// Schnorr signature implementation using the secp256k1 curve
// This is a simplified implementation for educational purposes

pub fn hash(r: &Scalar, pk: &Scalar, message: &str) -> Scalar {
    let mut hasher_input = Vec::new();
    // Convert BigUint to bytes for hashing
    hasher_input.extend(r.value.to_bytes_be());
    hasher_input.extend(pk.value.to_bytes_be());
    hasher_input.extend(message.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&hasher_input);
    let hash_result = hasher.finalize();

    // Convert the first 32 bytes of the hash to a BigUint
    let hash_value = BigUint::from_bytes_be(&hash_result);
    Scalar::new(hash_value)
}

pub struct Schnorr {
    private_key: Scalar,
    public_key: Scalar,
    g: Scalar, // Generator point (simplified as scalar for now)
}

impl Schnorr {
    pub fn new(private_key: Scalar) -> Self {
        // Use 2 as the generator point (simplified)
        let g = Scalar::new(BigUint::from(2u32));
        let public_key = &private_key * &g;
        Self { private_key, public_key, g }
    }

    pub fn sign(&self, message: &str) -> (Scalar, Scalar) {
        // 1. Generate a random number k (nonce)
        // In a real implementation, this should be cryptographically secure
        let k = Scalar::new(BigUint::from(100u32));

        // 2. Calculate r = k * G
        let r = &k * &self.g;

        // 3. Calculate e = hash(r || pk || message)
        let e = hash(&r, &self.public_key, message);

        // 4. Calculate s = k + e * private_key
        let s = &k + &(&e * &self.private_key);

        // Return signature (r, s)
        (r, s)
    }

    pub fn verify(&self, message: &str, signature: (Scalar, Scalar)) -> bool {
        let (r, s) = signature;

        // Calculate e = hash(r || pk || message)
        let e = hash(&r, &self.public_key, message);

        // Verify s * G = r + e * pk
        let left = &s * &self.g;
        let right = &r + &(&e * &self.public_key);

        left == right
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr() {
        // Create a new Schnorr instance with private key 1
        let schnorr = Schnorr::new(Scalar::new(BigUint::from(1u32)));

        // Sign a message
        let message = "hello";
        let signature = schnorr.sign(message);

        // Verify the signature
        assert!(schnorr.verify(message, signature));
    }

    #[test]
    fn test_different_messages() {
        let schnorr = Schnorr::new(Scalar::new(BigUint::from(1u32)));

        // Sign two different messages
        let message1 = "hello";
        let message2 = "world";

        let signature1 = schnorr.sign(message1);
        let signature2 = schnorr.sign(message2);

        // Verify correct signatures
        assert!(schnorr.verify(message1, (signature1.0.clone(), signature1.1.clone())));
        assert!(schnorr.verify(message2, (signature2.0.clone(), signature2.1.clone())));

        // Verify signatures don't work for wrong messages
        assert!(!schnorr.verify(message2, signature1));
        assert!(!schnorr.verify(message1, signature2));
    }

    #[test]
    fn test_different_keys() {
        let schnorr1 = Schnorr::new(Scalar::new(BigUint::from(1u32)));
        let schnorr2 = Schnorr::new(Scalar::new(BigUint::from(2u32)));

        let message = "hello";

        // Sign with first key
        let signature1 = schnorr1.sign(message);
        // Sign with second key
        let signature2 = schnorr2.sign(message);

        // Verify signatures with correct keys
        assert!(schnorr1.verify(message, (signature1.0.clone(), signature1.1.clone())));
        assert!(schnorr2.verify(message, (signature2.0.clone(), signature2.1.clone())));

        // Verify signatures fail with wrong keys
        assert!(!schnorr1.verify(message, signature2));
        assert!(!schnorr2.verify(message, signature1));
    }
}


