use sha2::{Sha256, Digest};
use rand::Rng;
use crate::scalar::Scalar;
use crate::field::FieldElement;
use crate::secp256k1::Point;
use num_bigint::BigUint;

/// Implements the Schnorr signature scheme over the secp256k1 curve.
/// This is a simplified implementation for educational purposes.

/// Computes the hash of (R || P || m) and returns it as a scalar.
/// This is used in both signing and verification.
pub fn hash(r: &Point, pk: &Point, message: &str) -> Scalar {
    let mut hasher_input = Vec::new();
    // Convert point coordinates to bytes for hashing
    hasher_input.extend(r.x.value().to_bytes_be());
    hasher_input.extend(r.y.value().to_bytes_be());
    hasher_input.extend(pk.x.value().to_bytes_be());
    hasher_input.extend(pk.y.value().to_bytes_be());
    hasher_input.extend(message.as_bytes());
    
    let mut hasher = Sha256::new();
    hasher.update(&hasher_input);
    let hash_result = hasher.finalize();
    
    // Convert the hash to a scalar
    let hash_value = BigUint::from_bytes_be(&hash_result);
    Scalar::new(hash_value)
}

/// The Schnorr signature scheme implementation
pub struct Schnorr {
    private_key: Scalar,
    public_key: Point,
    generator: Point, // The base point G
}

impl Schnorr {
    /// Creates a new Schnorr instance with the given private key.
    /// The public key is computed as P = private_key * G.
    pub fn new(private_key: Scalar) -> Self {
        let generator = Point::get_generator();
        let public_key = generator.scalar_mul(&private_key);
        Self { private_key, public_key, generator }
    }

    /// Signs a message using the Schnorr signature scheme.
    /// Returns (R, s) where:
    /// - R = k * G (for some random k)
    /// - s = k + e * private_key (where e = hash(R || P || message))
    pub fn sign(&self, message: &str) -> (Point, Scalar) {
        // Generate a random nonce k
        // In a real implementation, this should be cryptographically secure
        let k = Scalar::new(BigUint::from(100u32));
        
        // Calculate R = k * G
        let r = self.generator.scalar_mul(&k);
        
        // Calculate e = hash(R || P || message)
        let e = hash(&r, &self.public_key, message);
        
        // Calculate s = k + e * private_key
        let s = k.add(&e.mul(&self.private_key));
        
        (r, s)
    }

    /// Verifies a Schnorr signature (R, s) on a message.
    /// Checks if s * G = R + e * P where:
    /// - G is the generator point
    /// - P is the public key
    /// - e = hash(R || P || message)
    pub fn verify(&self, message: &str, signature: (Point, Scalar)) -> bool {
        let (r, s) = signature;
        
        // Calculate e = hash(R || P || message)
        let e = hash(&r, &self.public_key, message);
        
        // Calculate s * G
        let left = self.generator.scalar_mul(&s);
        
        // Calculate R + e * P
        let right = r.add(&self.public_key.scalar_mul(&e));
        
        // Verify s * G = R + e * P
        left == right
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_signature() {
        // Create a new Schnorr instance with private key 1
        let schnorr = Schnorr::new(Scalar::new(BigUint::from(1u32)));
        
        // Sign and verify a message
        let message = "hello";
        let signature = schnorr.sign(message);
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
        assert!(schnorr.verify(message1, signature1.clone()));
        assert!(schnorr.verify(message2, signature2.clone()));
        
        // Verify signatures don't work for wrong messages
        assert!(!schnorr.verify(message2, signature1));
        assert!(!schnorr.verify(message1, signature2));
    }

    #[test]
    fn test_different_keys() {
        let schnorr1 = Schnorr::new(Scalar::new(BigUint::from(1u32)));
        let schnorr2 = Schnorr::new(Scalar::new(BigUint::from(2u32)));
        
        let message = "hello";
        
        // Sign with both keys
        let signature1 = schnorr1.sign(message);
        let signature2 = schnorr2.sign(message);
        
        // Verify signatures with correct keys
        assert!(schnorr1.verify(message, signature1.clone()));
        assert!(schnorr2.verify(message, signature2.clone()));
        
        // Verify signatures fail with wrong keys
        assert!(!schnorr1.verify(message, signature2));
        assert!(!schnorr2.verify(message, signature1));
    }
}


