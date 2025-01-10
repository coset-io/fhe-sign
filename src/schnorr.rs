use sha2::{Sha256, Digest};
use rand::Rng;
use crate::scalar::{get_curve_order, Scalar, get_field_size};
use crate::field::FieldElement;
use crate::secp256k1::Point;
use std::ops::Sub;
use num_bigint::BigUint;
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

/// Converts a BigUint to a 32-byte array in big-endian format
fn bytes_from_int(n: &BigUint) -> [u8; 32] {
    let mut bytes = n.to_bytes_be();
    let mut result = [0u8; 32];
    let start = 32 - bytes.len();
    result[start..].copy_from_slice(&bytes);
    result
}

/// Converts a Point to a 32-byte array by taking its x-coordinate
fn bytes_from_point(p: &Point) -> [u8; 32] {
    bytes_from_int(&p.x.value())
}

/// Performs XOR operation on two byte slices
fn xor_bytes(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Converts a byte slice to a BigUint in big-endian format
fn int_from_bytes(b: &[u8]) -> BigUint {
    BigUint::from_bytes_be(b)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use rand_core::OsRng;
    use hex;

    #[test]
    fn test_schnorr_sign_computation() {
        // Test vector from the Python implementation
        let seckey_bytes = hex::decode("0000000000000000000000000000000000000000000000000000000000000003").unwrap();
        let pubkey_bytes = hex::decode("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9").unwrap();
        let aux_rand = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let message = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let signature = hex::decode("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0").unwrap();
        let aux_tag_hash = hex::decode("54f169cfc9e2e5727480441f90ba25c488f461c70b5ea5dcaaf7af69270aa514").unwrap();
        let nonce_tag_hash = hex::decode("1d2dc1652fee3ad08434469f9ad30536a5787feccfa308e8fb396c8030dd1c69").unwrap();
        let t_tag_hash = hex::decode("54f169cfc9e2e5727480441f90ba25c488f461c70b5ea5dcaaf7af69270aa517").unwrap();
        let k0_expected = BigUint::from_str("13197915491876976259551408334663313131887465579707439106007590226688883891305").unwrap();
        let k_expected = BigUint::from_str("102594173745439219164019576674024594720950098699367465276597572914829277603032").unwrap();
        let e_expected = BigUint::from_str("48720319366320448218248931228309816100339060958010591740548832691369990260430").unwrap();

        let seckey = Scalar::new(BigUint::from_bytes_be(&seckey_bytes));
        assert!(seckey.value() < &get_curve_order());

        let pubkey = Point::get_generator().scalar_mul(&seckey);
        assert_eq!(pubkey.x.value(), &BigUint::from_bytes_be(&pubkey_bytes));

        // d = d0 if has_even_y(P) else n - d0
        let d = if pubkey.y.value() % BigUint::from(2u32) == BigUint::from(0u32) {
            seckey.value().clone()
        } else {
            get_curve_order() - seckey.value().clone()
        };

        // aux tag hash
        // t = xor_bytes(bytes_from_int(d), aux_tag_hash)
        let t = xor_bytes(&bytes_from_int(&d), &aux_tag_hash[..]);
        let mut t_expected = [0u8; 32];
        t_expected.copy_from_slice(&t_tag_hash);
        assert_eq!(t, t_expected);

        // Create nonce input: t || bytes_from_point(P) || msg
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(&t);
        nonce_input.extend_from_slice(&bytes_from_point(&pubkey));
        nonce_input.extend_from_slice(&message);

        // nonce tag hash
        // k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)) % n
        let k0 = int_from_bytes(&tagged_hash(NONCE_TAG, &nonce_input)) % get_curve_order();
        assert_eq!(k0, k0_expected);
        // R = point_mul(G, k0)
        let r = Point::get_generator().scalar_mul(&Scalar::new(k0.clone()));

        // k = n - k0 if not has_even_y(R) else k0
        let k = if r.y.value() % BigUint::from(2u32) == BigUint::from(1u32) {
            get_curve_order() - k0.clone()
        } else {
            k0.clone()
        };
        assert_eq!(k, k_expected);
        // e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(R) + bytes_from_point(P) + msg)) % n
        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(&bytes_from_point(&r));
        challenge_input.extend_from_slice(&bytes_from_point(&pubkey));
        challenge_input.extend_from_slice(&message);
        // challenge tag hash
        let e = int_from_bytes(&tagged_hash(CHALLENGE_TAG, &challenge_input)) % get_curve_order();
        assert_eq!(e, e_expected);
        // sig = bytes_from_point(R) + bytes_from_int((k + e * d) % n)
        let mut sig = Vec::new();
        sig.extend_from_slice(&bytes_from_point(&r));
        sig.extend_from_slice(&bytes_from_int(&((k + e * d) % get_curve_order())));
        assert_eq!(sig, signature);
    }
}


