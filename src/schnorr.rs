use sha2::{Sha256, Digest};
use rand::Rng;
use crate::scalar::{get_curve_order, Scalar};
use crate::field::FieldElement;
use crate::secp256k1::Point;
use num_bigint::BigUint;

/// Implements the Schnorr signature scheme over the secp256k1 curve.
/// This is a simplified implementation for educational purposes.

/// Computes the tagged hash according to BIP340 specification.
/// The tag is used to prevent cross-protocol attacks by making the hash domain-specific.
fn tagged_hash(tag: &str, msg: &[u8]) -> Vec<u8> {
    // Compute the tag hash
    let mut tag_hasher = Sha256::new();
    tag_hasher.update(tag.as_bytes());
    let tag_hash = tag_hasher.finalize();

    // The tagged hash is SHA256(tag_hash || tag_hash || msg)
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(msg);
    hasher.finalize().to_vec()
}

/// Computes the hash of (R || P || m) and returns it as a scalar.
/// This follows the BIP340 specification for Schnorr signatures.
pub fn hash(r: &Point, pk: &Point, message: &str) -> Scalar {
    let mut hasher_input = Vec::new();

    // According to BIP340, we only use the x-coordinate of points
    // and we need to serialize them as 32-byte arrays
    let mut r_bytes = r.x.value().to_bytes_be();
    // Pad to 32 bytes if necessary
    while r_bytes.len() < 32 {
        r_bytes.insert(0, 0);
    }

    let mut pk_bytes = pk.x.value().to_bytes_be();
    while pk_bytes.len() < 32 {
        pk_bytes.insert(0, 0);
    }

    // Concatenate the bytes: R || P || m
    hasher_input.extend_from_slice(&r_bytes);
    hasher_input.extend_from_slice(&pk_bytes);
    hasher_input.extend_from_slice(message.as_bytes());

    // Use the BIP340/challenge tag for the main signature hash
    let hash_result = tagged_hash("BIP340/challenge", &hasher_input);

    // Convert the hash to a scalar modulo the curve order
    let hash_value = BigUint::from_bytes_be(&hash_result) % get_curve_order();
    Scalar::new(hash_value)
}

/// Computes the hash of the auxiliary random data.
/// This is used in the nonce generation process according to BIP340.
pub fn hash_aux(aux_rand: &[u8]) -> Vec<u8> {
    tagged_hash("BIP340/aux", aux_rand)
}

/// Computes the hash for nonce generation.
/// According to BIP340, the nonce is derived from the private key, message, and optional auxiliary random data.
pub fn hash_nonce(secret_key: &Scalar, message: &str, aux_rand: Option<&[u8]>) -> Scalar {
    let mut hasher_input = Vec::new();

    // Convert secret key to 32-byte array
    let mut sk_bytes = secret_key.value().to_bytes_be();
    while sk_bytes.len() < 32 {
        sk_bytes.insert(0, 0);
    }

    // If auxiliary randomness is provided, hash it first
    if let Some(aux) = aux_rand {
        let aux_hash = hash_aux(aux);
        hasher_input.extend_from_slice(&aux_hash);
    }

    // Add secret key and message
    hasher_input.extend_from_slice(&sk_bytes);
    hasher_input.extend_from_slice(message.as_bytes());

    // Use the BIP340/nonce tag
    let hash_result = tagged_hash("BIP340/nonce", &hasher_input);

    // Convert to scalar
    let hash_value = BigUint::from_bytes_be(&hash_result) % get_curve_order();
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
        // Generate deterministic nonce according to BIP340
        let k = hash_nonce(&self.private_key, message, None);

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
        println!("Signature: {:?}", signature);
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


