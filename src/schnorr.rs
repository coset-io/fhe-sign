use sha2::{Sha256, Digest};
use crate::scalar::{get_curve_order, Scalar, get_field_size};
use crate::field::FieldElement;
use crate::secp256k1::Point;
use num_bigint::BigUint;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, ClientKey};
use crate::biguint::BigUintFHE;
use std::time::Instant;

// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

// Input:
// - The secret key sk: a 32-byte array
// - The message m: a byte array
// - Auxiliary random data a: a 32-byte array

// The algorithm Sign(sk, m) is defined as:
// - Let d' = int(sk)
// - Fail if d' = 0 or d' ≥ n
// - Let P = d'⋅G
// - Let d = d' if has_even_y(P), otherwise let d = n - d' .
// - Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a)[11].
// - Let rand = hashBIP0340/nonce(t || bytes(P) || m)[12].
// - Let k' = int(rand) mod n[13].
// - Fail if k' = 0.
// - Let R = k'⋅G.
// - Let k = k' if has_even_y(R), otherwise let k = n - k' .
// - Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
// - Let sig = bytes(R) || bytes((k + ed) mod n).
// - If Verify(bytes(P), m, sig) (see below) returns failure, abort[14].
// - Return the signature sig.

/// BIP-340 tag constants for domain separation
const AUX_TAG: &[u8] = b"BIP0340/aux";
const NONCE_TAG: &[u8] = b"BIP0340/nonce";
const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

/// Represents a Schnorr signature according to BIP-340
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    pub r_x: FieldElement,  // x-coordinate of R
    pub s: Scalar,         // scalar s
}

impl Signature {
    /// Serializes the signature to bytes according to BIP-340: R.x || s
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut sig = Vec::with_capacity(64);
        sig.extend_from_slice(&bytes_from_int(&self.r_x.value()));
        sig.extend_from_slice(&bytes_from_int(self.s.value()));
        sig
    }
}

/// The Schnorr signature scheme implementation following BIP-340
pub struct Schnorr {
}

impl Schnorr {
    /// Creates a new Schnorr instance with the given private key.
    pub fn new() -> Self {
        Self {}
    }

    /// Signs a message using the Schnorr signature scheme according to BIP-340.
    ///
    /// Arguments:
    /// * `message` - The message to be signed as a byte slice
    /// * `aux_rand` - The auxiliary random data as a byte slice
    /// * `privkey` - The caller/owner's private key as a Scalar
    ///
    /// Returns:
    /// * `Result<Signature, Box<dyn std::error::Error>>` - The Schnorr signature if successful, or an error if the operation fails
    pub fn sign(&self, message: &[u8], aux_rand: &[u8], privkey: &Scalar) -> Result<Signature, Box<dyn std::error::Error>> {
        println!("Starting `sign` operation");
        let start_total = Instant::now();
        let pubkey = get_public_key_with_even_y(privkey);
        let curve_order = get_curve_order();
        // Generate deterministic nonce k0 according to BIP-340
        let k0 = compute_nonce(privkey.value(), &pubkey, message, aux_rand);
        let generator = Point::get_generator();
        let r = generator.scalar_mul(&Scalar::new(k0.clone()));

        // Adjust k based on R's y-coordinate parity
        let k = if r.y.value() % BigUint::from(2u32) == BigUint::from(1u32) {
            &curve_order - k0
        } else {
            k0
        };

        // Compute challenge e = hash(R || P || message)
        let e = compute_challenge(&r, &pubkey, message);

        // Compute s = (k + e * privkey) % n
        let s = (k + e * privkey.value()) % get_curve_order();
        println!("`sign` operation time: {:?}", start_total.elapsed());

        Ok(Signature {
            r_x: r.x,
            s: Scalar::new(s),
        })
    }

    /// Signs a message using the Schnorr signature scheme according to BIP-340.
    ///
    /// Arguments:
    /// * `message` - The message to be signed as a byte slice
    /// * `k0` - The pre-computed nonce value as a BigUint
    /// * `privkey` - The caller/owner's private key as a Scalar
    ///
    /// Returns:
    /// * `Result<Signature, Box<dyn std::error::Error>>` - The Schnorr signature if successful, or an error if the operation fails
    pub fn sign_with_k0(&self, message: &[u8], k0: &BigUint, privkey: &Scalar) -> Result<Signature, Box<dyn std::error::Error>> {
        println!("Starting `sign` operation");
        let start_total = Instant::now();
        let pubkey = get_public_key_with_even_y(privkey);
        let curve_order = get_curve_order();
        // Generate deterministic nonce k0 according to BIP-340
        let generator = Point::get_generator();
        let r = generator.scalar_mul(&Scalar::new(k0.clone()));

        // Adjust k based on R's y-coordinate parity
        let k = if r.y.value() % BigUint::from(2u32) == BigUint::from(1u32) {
            &curve_order - k0
        } else {
            k0.clone()
        };

        // Compute challenge e = hash(R || P || message)
        let e = compute_challenge(&r, &pubkey, message);

        // Compute s = (k + e * privkey) % n
        let s = (k + e * privkey.value()) % get_curve_order();
        println!("`sign` operation time: {:?}", start_total.elapsed());

        Ok(Signature {
            r_x: r.x,
            s: Scalar::new(s),
        })
    }


    /// Signs a message using the Schnorr signature scheme according to BIP-340 with FHE.
    ///
    /// # Arguments
    /// * `message` - The message to be signed as a byte slice
    /// * `aux_rand` - The auxiliary random data as a byte slice
    /// * `privkey` - The caller/owner's private key as a Scalar
    /// * `client_key` - The FHE client key used for encryption/decryption
    ///
    /// # Returns
    /// * `Result<Signature, tfhe::Error>` - The Schnorr signature if successful, or a TFHE error if encryption operations fail
    pub fn sign_fhe(&self, message: &[u8], aux_rand: &[u8], privkey: &Scalar, client_key: &ClientKey) -> Result<Signature, tfhe::Error> {
        let start_total = Instant::now();
        println!("Starting `sign_fhe` operation");

        // Step 1: Get Public Key
        let start_public_key = Instant::now();
        let pubkey = get_public_key_with_even_y(privkey);
        println!("`get_public_key` time: {:?}", start_public_key.elapsed());

        let curve_order = get_curve_order();

        // Step 2: Compute Nonce
        let start_nonce = Instant::now();
        let k0 = compute_nonce(privkey.value(), &pubkey, message, aux_rand);
        println!("`compute_nonce` time: {:?}", start_nonce.elapsed());

        // Step 3: Compute R = kG
        let generator = Point::get_generator();
        let start_r = Instant::now();
        let r = generator.scalar_mul(&Scalar::new(k0.clone()));
        println!("`scalar_mul` (computing R) time: {:?}", start_r.elapsed());

        // Step 4: Adjust k based on R's y-coordinate parity
        let start_adjust_k = Instant::now();
        let k = if r.y.value() % BigUint::from(2u32) == BigUint::from(1u32) {
            &curve_order - k0
        } else {
            k0
        };
        println!("`adjust_k` time: {:?}", start_adjust_k.elapsed());

        // Step 5: Compute Challenge e = H(R || P || m)
        let start_challenge = Instant::now();
        let e = compute_challenge(&r, &pubkey, message);
        println!("`compute_challenge` time: {:?}", start_challenge.elapsed());

        // Step 6: Compute s = (k + e * privkey) mod n using FHE operations
        let start_fhe_operations = Instant::now();
        let privkey_fhe = BigUintFHE::new(privkey.value().clone(), client_key)?;
        let e_fhe = BigUintFHE::new(e.clone(), client_key)?;
        let k_fhe = BigUintFHE::new(k.clone(), client_key)?;
        let s_fhe_without_mod = k_fhe + (e_fhe * privkey_fhe);
        let s_without_mod = s_fhe_without_mod.to_biguint(client_key);
        let s = s_without_mod % curve_order;
        println!("FHE operations (`k + e * privkey mod n`) time: {:?}", start_fhe_operations.elapsed());

        // Step 7: Construct the Signature
        let start_construct_signature = Instant::now();
        let signature = Signature {
            r_x: r.x,
            s: Scalar::new(s),
        };
        println!("`construct_signature` time: {:?}", start_construct_signature.elapsed());

        println!("Total `sign_fhe` operation time: {:?}", start_total.elapsed());

        Ok(signature)
    }

    /// Signs a message using the Schnorr signature scheme according to BIP-340 with FHE.
    /// problem: we do not want to involve private key in nonce computation, because it uses hash operation which is very expensive
    /// solution exploration:
    /// 1. since k0 is used as a random number, which is computed with private key and other message. this can generate a unique random number for each message.
    /// 2. if we can use other number rather than private key to generate k0, we can avoid the expensive hash operation. so we only need to calculate signature with private key(encrypted form) involved in the formula s = (k + e * privkey) mod n
    /// 3. considering our use case, alice store the main private key in encrypted form, then set access control rules, allow alice's working device to call the sign function, the working device also has a key pair which is visible to alice due to alice owns the working device. so we can use the working device's private key to generate k0. this avoid the expensive hash operation.
    /// 4. remind that we want to avoid the expensive hash operation, we need to use the working device's private key to in clear/unencrypted form, but we can not pass the private key as parameter to the sign function which happens onchain and publically visible to all. so we need the device to generate k0 with its private key offchain privately, and then pass k0 to the sign function.
    /// 5. addtional work for security reason
    /// 5.1 if the working device is compromised, the private key can be leaked. so we need to ensure the sign function is still secure, which means cracker can not get alice's private key from s = (k + e * privkey) mod n, which means k0 should be unique for each signature.
    /// 5.2 so we need to store the k0 values on chain, each sign operation need to check if the k0 is already used before.

    /// Signs a message using the Schnorr signature scheme according to BIP-340 with FHE and a pre-computed nonce k0.
    ///
    /// # Arguments
    /// * `message` - The message to be signed as a byte slice
    /// * `k0` - The pre-computed nonce value as a BigUint
    /// * `privkey` - The caller's private key as a Scalar
    /// * `privkey_fhe` - The owner's private key encrypted as a BigUintFHE
    /// * `client_key` - The FHE client key used for encryption/decryption
    ///
    /// # Returns
    /// * `Result<Signature, tfhe::Error>` - The Schnorr signature if successful, or a TFHE error if encryption operations fail
    pub fn sign_fhe_with_k0(&self, message: &[u8], k0: &BigUint, privkey: &Scalar, privkey_fhe: &BigUintFHE, client_key: &ClientKey) -> Result<Signature, tfhe::Error> {
        let start_total = Instant::now();
        println!("Starting `sign_fhe` operation");

        // Step 1: Get Public Key
        let start_public_key = Instant::now();
        let pubkey = get_public_key_with_even_y(privkey);
        println!("`get_public_key` time: {:?}", start_public_key.elapsed());

        let curve_order = get_curve_order();

        // Step 2: Compute Nonce
        let start_nonce = Instant::now();
        println!("`compute_nonce` time: {:?}", start_nonce.elapsed());

        // Step 3: Compute R = kG
        let generator = Point::get_generator();
        let start_r = Instant::now();
        let r = generator.scalar_mul(&Scalar::new(k0.clone()));
        println!("`scalar_mul` (computing R) time: {:?}", start_r.elapsed());

        // Step 4: Adjust k based on R's y-coordinate parity
        let start_adjust_k = Instant::now();
        let k = if r.y.value() % BigUint::from(2u32) == BigUint::from(1u32) {
            &curve_order - k0.clone()
        } else {
            k0.clone()
        };
        println!("`adjust_k` time: {:?}", start_adjust_k.elapsed());

        // Step 5: Compute Challenge e = H(R || P || m)
        let start_challenge = Instant::now();
        let e = compute_challenge(&r, &pubkey, message);
        println!("`compute_challenge` time: {:?}", start_challenge.elapsed());

        // Step 6: Compute s = (k + e * privkey) mod n using FHE operations
        let start_fhe_operations = Instant::now();
        let e_fhe = BigUintFHE::new(e.clone(), client_key)?;
        let k_fhe = BigUintFHE::new(k.clone(), client_key)?;
        let s_fhe_without_mod = k_fhe + (e_fhe * privkey_fhe.clone());
        let s_without_mod = s_fhe_without_mod.to_biguint(client_key);
        let s = s_without_mod % curve_order;
        println!("FHE operations (`k + e * privkey mod n`) time: {:?}", start_fhe_operations.elapsed());

        // Step 7: Construct the Signature
        let start_construct_signature = Instant::now();
        let signature = Signature {
            r_x: r.x,
            s: Scalar::new(s),
        };
        println!("`construct_signature` time: {:?}", start_construct_signature.elapsed());

        println!("Total `sign_fhe` operation time: {:?}", start_total.elapsed());

        Ok(signature)
    }

    /// Verifies a Schnorr signature according to BIP-340.
    ///
    /// Arguments:
    /// * `message` - The message to be signed as a byte slice
    /// * `pubkey_bytes` - The public key as a byte slice
    /// * `sig_bytes` - The signature as a byte slice
    ///
    /// Returns:
    /// * `bool` - True if the signature is valid, false otherwise
    pub fn verify(message: &[u8], pubkey_bytes: &[u8], sig_bytes: &[u8]) -> bool {
        // Check input lengths
        if pubkey_bytes.len() != 32 || sig_bytes.len() != 64 {
            return false;
        }

        // Parse signature and public key
        let sig = Signature {
            r_x: FieldElement::new(BigUint::from_bytes_be(&sig_bytes[0..32]), get_field_size()),
            s: Scalar::new(BigUint::from_bytes_be(&sig_bytes[32..64])),
        };

        // Lift x coordinates to curve points
        let pubkey = FieldElement::new(BigUint::from_bytes_be(pubkey_bytes), get_field_size());
        let pubkey_point = lift_x(&pubkey);
        if pubkey_point.is_infinity {
            return false;
        }

        // Reconstruct R point from x-coordinate
        let r_point = {
            let x3 = &sig.r_x * &sig.r_x * &sig.r_x;
            let r_y_squared = x3 + FieldElement::new(BigUint::from(7u32), get_field_size());
            let mut r_y = r_y_squared.sqrt();
            if r_y.value() % BigUint::from(2u32) == BigUint::from(1u32) {
                r_y = FieldElement::new(get_field_size() - r_y.value(), get_field_size());
            }
            Point::new(sig.r_x.clone(), r_y, false)
        };

        // Verify signature bounds
        if r_point.x.value() >= &get_curve_order() || sig.s.value() >= &get_curve_order() {
            return false;
        }

        // Compute sG and eP
        let generator = Point::get_generator();
        let s_g = generator.scalar_mul(&sig.s);
        let e = Scalar::new(compute_challenge(&r_point, &pubkey_point, message));
        let e_p = pubkey_point.scalar_mul(&e);

        // Verify R = sG - eP and has even y-coordinate
        let r_computed = s_g - e_p;
        !(r_computed.is_infinity
          || r_computed.y.value() % BigUint::from(2u32) == BigUint::from(1u32)
          || r_computed.x.value() != sig.r_x.value())
    }
}


/// Gets the public key with BIP-340 y-coordinate conventions which is even
fn get_public_key_with_even_y(privkey: &Scalar) -> Point {
    let generator = Point::get_generator();
    let pubkey = generator.scalar_mul(&privkey);

    // Ensure the public key has an even y-coordinate as per BIP-340
    if pubkey.y.value() % BigUint::from(2u32) == BigUint::from(1u32) {
        Point::new(
            pubkey.x.clone(),
            FieldElement::new(get_field_size() - pubkey.y.value(), get_field_size()),
            false
        )
    } else {
        pubkey
    }
}

/// Computes the tagged hash according to BIP-340 specification.
/// tagged_hash = SHA256(SHA256(tag) || SHA256(tag) || msg)
fn tagged_hash(tag: &[u8], msg: &[u8]) -> Vec<u8> {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(msg);
    hasher.finalize().to_vec()
}

/// Converts a BigUint to a 32-byte array in big-endian format
fn bytes_from_int(n: &BigUint) -> [u8; 32] {
    let bytes = n.to_bytes_be();
    let mut result = [0u8; 32];
    let start = 32 - bytes.len();
    result[start..].copy_from_slice(&bytes);
    result
}

/// Converts a Point to a 32-byte array by taking its x-coordinate
fn bytes_from_point(p: &Point) -> [u8; 32] {
    bytes_from_int(&p.x.value())
}

/// Computes the nonce according to BIP-340 specification
fn compute_nonce(privkey: &BigUint, pubkey: &Point, message: &[u8], aux_rand: &[u8]) -> BigUint {
    let t = xor_bytes(&bytes_from_int(privkey), &tagged_hash(AUX_TAG, aux_rand));
    let mut nonce_input = Vec::new();
    nonce_input.extend_from_slice(&t);
    nonce_input.extend_from_slice(&bytes_from_point(pubkey));
    nonce_input.extend_from_slice(message);
    BigUint::from_bytes_be(&tagged_hash(NONCE_TAG, &nonce_input)) % get_curve_order()
}

/// Computes the challenge according to BIP-340 specification
fn compute_challenge(r: &Point, pubkey: &Point, message: &[u8]) -> BigUint {
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(&bytes_from_point(r));
    challenge_input.extend_from_slice(&bytes_from_point(pubkey));
    challenge_input.extend_from_slice(message);
    BigUint::from_bytes_be(&tagged_hash(CHALLENGE_TAG, &challenge_input)) % get_curve_order()
}

/// Performs XOR operation on two 32-byte slices
fn xor_bytes(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Lifts an x-coordinate to a point on the curve with even y-coordinate
fn lift_x(x: &FieldElement) -> Point {
    if x.value() >= &get_curve_order() {
        return Point::infinity();
    }
    let y_squared = x.pow(&BigUint::from(3u32)) + FieldElement::new(BigUint::from(7u32), x.order().clone());
    let mut y = y_squared.sqrt();
    if y.value() % BigUint::from(2u32) == BigUint::from(1u32) {
        y = FieldElement::new(x.order().clone() - y.value(), x.order().clone());
    }
    Point::new(x.clone(), y, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_schnorr_fhe() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_keys) = generate_keys(config);
        set_server_key(server_keys);

        // Test vector from BIP-340
        let seckey_bytes = hex::decode("0000000000000000000000000000000000000000000000000000000000000003").unwrap();
        let message = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let aux_rand = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let expected_sig = hex::decode("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0").unwrap();

        let seckey = Scalar::new(BigUint::from_bytes_be(&seckey_bytes));
        let schnorr = Schnorr::new();
        let sig = schnorr.sign(&message, &aux_rand, &seckey);
        let pubkey = get_public_key_with_even_y(&seckey);

        assert!(sig.is_ok());
        let sig = sig.unwrap();
        assert_eq!(sig.to_bytes(), expected_sig);
        assert!(Schnorr::verify(&message, &pubkey.x.value().to_bytes_be(), &expected_sig));

        let sig_fhe = schnorr.sign_fhe(&message, &aux_rand, &seckey, &client_key);
        assert!(sig_fhe.is_ok());
        let sig_fhe = sig_fhe.unwrap();
        assert_eq!(sig_fhe.to_bytes(), expected_sig);
        assert!(Schnorr::verify(&message, &pubkey.x.value().to_bytes_be(), &expected_sig));
    }

    #[test]
    fn test_schnorr_fhe_with_k0() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_keys) = generate_keys(config);
        set_server_key(server_keys);

        // Test vector from BIP-340
        let seckey_bytes = hex::decode("0000000000000000000000000000000000000000000000000000000000000003").unwrap();
        let message = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let aux_rand = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let privkey = Scalar::new(BigUint::from_bytes_be(&seckey_bytes));
        let privkey_fhe = BigUintFHE::new(privkey.value().clone(), &client_key).unwrap();
        let pubkey = get_public_key_with_even_y(&privkey);

        let schnorr = Schnorr::new();
        let k0 = compute_nonce(&privkey.value(), &pubkey, &message, &aux_rand);
        // sign with k0
        let sig_with_k0 = schnorr.sign_with_k0(&message, &k0, &privkey).unwrap();
        // sign fhe with k0
        let sig_fhe_with_k0 = schnorr.sign_fhe_with_k0(&message, &k0, &privkey, &privkey_fhe, &client_key).unwrap();

        assert_eq!(sig_with_k0.to_bytes(), sig_fhe_with_k0.to_bytes());
        assert!(Schnorr::verify(&message, &pubkey.x.value().to_bytes_be(), &sig_with_k0.to_bytes()));
    }

    #[test]
    fn test_schnorr_bip340() {
        // Test vector from BIP-340
        let seckey_bytes = hex::decode("0000000000000000000000000000000000000000000000000000000000000003").unwrap();
        let message = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let aux_rand = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let expected_sig = hex::decode("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0").unwrap();

        let seckey = Scalar::new(BigUint::from_bytes_be(&seckey_bytes));
        let schnorr = Schnorr::new();
        let sig = schnorr.sign(&message, &aux_rand, &seckey);
        assert!(sig.is_ok());
        let sig = sig.unwrap();
        let pubkey = get_public_key_with_even_y(&seckey);

        assert_eq!(sig.to_bytes(), expected_sig);
        assert!(Schnorr::verify(&message, &pubkey.x.value().to_bytes_be(), &expected_sig));
    }

    #[test]
    fn test_schnorr_with_k0() {
        let seckey_bytes = hex::decode("0000000000000000000000000000000000000000000000000000000000000003").unwrap();
        let message = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let aux_rand = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let privkey = Scalar::new(BigUint::from_bytes_be(&seckey_bytes));
        let schnorr = Schnorr::new();
        let pubkey = get_public_key_with_even_y(&privkey);
        let k0 = compute_nonce(&privkey.value(), &pubkey, &message, &aux_rand);
        let sig_with_k0 = schnorr.sign_with_k0(&message, &k0, &privkey).unwrap();

        let sig = schnorr.sign(&message, &aux_rand, &privkey).unwrap();

        assert_eq!(sig.to_bytes(), sig_with_k0.to_bytes());
        assert!(Schnorr::verify(&message, &pubkey.x.value().to_bytes_be(), &sig_with_k0.to_bytes()));
    }

    #[test]
    fn test_schnorr_vectors() {
        let csv_content = include_str!("../tests/test_vectors.csv");
        let mut all_passed = true;

        for (i, line) in csv_content.lines().skip(1).enumerate() {
            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() < 7 { continue; }

            let (index, seckey_hex, pubkey_hex, aux_rand_hex, msg_hex, sig_hex, result_str) =
                (fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6]);
            let expected_result = result_str == "TRUE";

            let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
            let message = hex::decode(msg_hex).unwrap();
            let expected_sig = hex::decode(sig_hex).unwrap();

            if !seckey_hex.is_empty() {
                let seckey_bytes = hex::decode(seckey_hex).unwrap();
                let aux_rand = hex::decode(aux_rand_hex).unwrap();
                let seckey = Scalar::new(BigUint::from_bytes_be(&seckey_bytes));
                let schnorr = Schnorr::new();

                let sig = schnorr.sign(&message, &aux_rand, &seckey);
                assert!(sig.is_ok());
                let sig = sig.unwrap();
                if sig.to_bytes() != expected_sig {
                    println!("Failed signing test for vector #{}", index);
                    all_passed = false;
                    continue;
                }
            }

            let result = Schnorr::verify(&message, &pubkey_bytes, &expected_sig);
            if result != expected_result {
                println!("Failed verification test for vector #{}", index);
                all_passed = false;
                continue;
            }
        }

        assert!(all_passed, "Some test vectors failed");
    }

    #[test]
    fn test_fheu32_mul_u32() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_keys) = generate_keys(config);
        set_server_key(server_keys);

        // Test FHE multiplication with plain value
        let value = 123u32;
        let multiplier = 456u32;
        let expected = value * multiplier;
        // Encrypt the value
        let encrypted = FheUint32::try_encrypt(value, &client_key).unwrap();

        // Multiply encrypted value with plain value
        let result_fhe = encrypted * multiplier;
        // Decrypt and verify
        let decrypted: u32 = result_fhe.decrypt(&client_key);
        assert_eq!(decrypted, expected);
    }

    #[test]
    fn test_fheu32_add_u32() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_keys) = generate_keys(config);
        set_server_key(server_keys);

        let value = 123u32;
        let addend = 456u32;
        let expected = value + addend;
        let encrypted = FheUint32::try_encrypt(value, &client_key).unwrap();
        let result_fhe = encrypted + addend;
        let decrypted: u32 = result_fhe.decrypt(&client_key);
        assert_eq!(decrypted, expected);
    }
}


