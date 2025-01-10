use sha2::{Sha256, Digest};
use rand::Rng;
use crate::scalar::{get_curve_order, Scalar, get_field_size};
use crate::field::FieldElement;
use crate::secp256k1::Point;
use num_bigint::BigUint;
use k256::schnorr::{SigningKey, Signature as K256Signature};
use k256::schnorr::signature::{Signer, Verifier};
use hex;

/// BIP-340 tag constants
const AUX_TAG: &[u8] = b"BIP0340/aux";
const NONCE_TAG: &[u8] = b"BIP0340/nonce";
const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

/// Implements the Schnorr signature scheme over the secp256k1 curve.
/// This implementation follows BIP-340 specification.

/// Computes the tagged hash according to BIP340 specification.
/// The tag is used to prevent cross-protocol attacks by making the hash domain-specific.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut tag_hasher = Sha256::new();
    tag_hasher.update(tag);
    let tag_hash = tag_hasher.finalize();

    // The tagged hash is SHA256(tag_hash || tag_hash || msg)
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(msg);
    hasher.finalize().to_vec()
}

/// Serializes a field element to a 32-byte array in big-endian format
fn serialize_field_element(fe: &FieldElement) -> [u8; 32] {
    let mut bytes = fe.value().to_bytes_be();
    let mut result = [0u8; 32];
    let start = 32 - bytes.len();
    result[start..].copy_from_slice(&bytes);
    result
}

/// Computes the hash of (R || P || m) and returns it as a scalar.
/// This follows the BIP340 specification for Schnorr signatures.
pub fn hash(r: &Point, pk: &Point, message: &str) -> Scalar {
    let mut hasher_input = Vec::new();

    // According to BIP340, we only use the x-coordinate of points
    hasher_input.extend_from_slice(&serialize_field_element(&r.x));
    hasher_input.extend_from_slice(&serialize_field_element(&pk.x));
    hasher_input.extend_from_slice(message.as_bytes());

    let hash_result = tagged_hash(CHALLENGE_TAG, &hasher_input);
    let hash_value = BigUint::from_bytes_be(&hash_result) % get_curve_order();
    Scalar::new(hash_value)
}

/// Computes the hash for nonce generation.
/// According to BIP340, the nonce is derived from the private key, message, and optional auxiliary random data.
pub fn hash_nonce(secret_key: &Scalar, message: &str, aux_rand: Option<&[u8]>) -> Scalar {
    let mut hasher_input = Vec::new();

    if let Some(aux) = aux_rand {
        let aux_hash = tagged_hash(AUX_TAG, aux);
        hasher_input.extend_from_slice(&aux_hash);
    }

    hasher_input.extend_from_slice(&serialize_field_element(secret_key.as_field_element()));
    hasher_input.extend_from_slice(message.as_bytes());

    let hash_result = tagged_hash(NONCE_TAG, &hasher_input);
    let hash_value = BigUint::from_bytes_be(&hash_result) % get_curve_order();
    Scalar::new(hash_value)
}

/// Represents a Schnorr signature according to BIP-340
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    pub r_x: FieldElement,  // x-coordinate of R
    pub s: Scalar,         // scalar s
}

impl Signature {
    /// Converts the signature to bytes according to BIP-340
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&serialize_field_element(&self.r_x));
        bytes.extend_from_slice(&serialize_field_element(self.s.as_field_element()));
        bytes
    }
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

        // Ensure the public key has an even y-coordinate as per BIP-340
        let pk = if public_key.y.value() % BigUint::from(2u32) == BigUint::from(1u32) {
            // If y is odd, negate the point
            Point::new(
                public_key.x.clone(),
                FieldElement::new(get_field_size() - public_key.y.value(), get_field_size()),
                false
            )
        } else {
            public_key
        };

        Self { private_key, public_key: pk, generator }
    }

    /// Signs a message using the Schnorr signature scheme according to BIP-340.
    pub fn sign(&self, message: &str) -> Signature {
        // Generate deterministic nonce according to BIP340
        let k = hash_nonce(&self.private_key, message, None);

        // Calculate R = k * G
        let r = self.generator.scalar_mul(&k);

        // Ensure R has even y-coordinate
        let (r_final, k_final) = if r.y.value() % BigUint::from(2u32) == BigUint::from(1u32) {
            // If y is odd, negate k and recompute R
            let k_neg = k.neg();
            let r_neg = self.generator.scalar_mul(&k_neg);
            (r_neg, k_neg)
        } else {
            (r.clone(), k)
        };

        // Calculate e = hash(R || P || message)
        let e = hash(&r_final, &self.public_key, message);

        // Calculate s = k + e * private_key
        let s = k_final.add(&e.mul(&self.private_key));

        Signature {
            r_x: r_final.x,
            s,
        }
    }

    /// Verifies a Schnorr signature according to BIP-340.
    pub fn verify(&self, message: &str, signature: &Signature) -> bool {
        // Reconstruct R point from x-coordinate
        let x3 = &signature.r_x * &signature.r_x * &signature.r_x;
        let seven = FieldElement::new(BigUint::from(7u32), get_field_size());
        let r_y_squared = (x3 + seven).clone();

        // Calculate s * G
        let s_g = self.generator.scalar_mul(&signature.s);

        // Calculate e * P
        let r_point = Point::new(signature.r_x.clone(), r_y_squared.clone(), false);
        let e = hash(&r_point, &self.public_key, message);
        let e_p = self.public_key.scalar_mul(&e);

        // Check that s * G = R + e * P by comparing x-coordinates
        // This is equivalent to checking if R = s * G - e * P has the claimed x-coordinate
        let r_computed = s_g - e_p;

        // The signature is valid if:
        // 1. r_x is a valid x-coordinate (implied by Point construction)
        // 2. s is less than the curve order (implied by Scalar construction)
        // 3. The computed R matches the signature's R x-coordinate
        r_computed.x == signature.r_x
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::{SigningKey, VerifyingKey};
    use rand_core::OsRng;
    use hex;

    // Test vector from BIP-340
    const TEST_VECTOR: &str = "\
        0000000000000000000000000000000000000000000000000000000000000003\
        F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9\
        7C68F1189B2CBD11C92D6B0874C55B8A161A2496D1238A7C946193F59820B99A\
        0AC4F2B36462DB9AC3DAFB6154E2A6A7C7B73AEC470B42FFA2D9B65C36469492\
        6666666666666666666666666666666666666666666666666666666666666658";

    #[test]
    fn test_bip340_vector() {
        // Parse test vector
        let private_key_bytes = hex::decode(&TEST_VECTOR[..64]).unwrap();
        let public_key_x = hex::decode(&TEST_VECTOR[64..128]).unwrap();
        let message = hex::decode(&TEST_VECTOR[128..192]).unwrap();
        let expected_sig = hex::decode(&TEST_VECTOR[192..]).unwrap();

        // Create our implementation's signature
        let private_key = Scalar::new(BigUint::from_bytes_be(&private_key_bytes));
        let schnorr = Schnorr::new(private_key);
        let signature = schnorr.sign(std::str::from_utf8(&message).unwrap());

        // Verify signature matches test vector
        let sig_bytes = signature.to_bytes();
        assert_eq!(sig_bytes, expected_sig);
    }

    #[test]
    fn test_schnorr_signature() {
        // Create a new Schnorr instance with private key 1
        let schnorr = Schnorr::new(Scalar::new(BigUint::from(1u32)));

        // Sign and verify a message
        let message = "hello";
        let signature = schnorr.sign(message);
        assert!(schnorr.verify(message, &signature));
    }

    #[test]
    fn test_different_messages() {
        let schnorr = Schnorr::new(Scalar::new(BigUint::from(1u32)));

        let message1 = "hello";
        let message2 = "world";

        let signature1 = schnorr.sign(message1);
        let signature2 = schnorr.sign(message2);

        assert!(schnorr.verify(message1, &signature1));
        assert!(schnorr.verify(message2, &signature2));

        assert!(!schnorr.verify(message2, &signature1));
        assert!(!schnorr.verify(message1, &signature2));
    }

    #[test]
    fn test_different_keys() {
        let schnorr1 = Schnorr::new(Scalar::new(BigUint::from(1u32)));
        let schnorr2 = Schnorr::new(Scalar::new(BigUint::from(2u32)));

        let message = "hello";

        let signature1 = schnorr1.sign(message);
        let signature2 = schnorr2.sign(message);

        assert!(schnorr1.verify(message, &signature1));
        assert!(schnorr2.verify(message, &signature2));

        assert!(!schnorr1.verify(message, &signature2));
        assert!(!schnorr2.verify(message, &signature1));
    }
}


