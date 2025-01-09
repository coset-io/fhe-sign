use sha2::{Sha256, Digest};
use rand::Rng;
use crate::scalar::Scalar;

pub fn hash(r: &Scalar, pk: &Scalar, message: &str) -> Scalar {
    let mut hasher_input = Vec::new();
    hasher_input.extend(&r.value.to_be_bytes());
    hasher_input.extend(&pk.value.to_be_bytes());
    hasher_input.extend(message.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&hasher_input);
    let hash_result = hasher.finalize();
    let result = u32::from_be_bytes(hash_result[..4].try_into().expect("Hash output too short"));
    Scalar::new(result)
}

pub struct Schnorr {
    private_key: Scalar,
    public_key: Scalar,
    g: Scalar, // todo: elliptic curve point
}

impl Schnorr {
    pub fn new(private_key: Scalar) -> Self {
        let g = Scalar::new(2); // Define G
        let public_key = &private_key * &g;
        Self { private_key, public_key, g }
    }

    pub fn sign(&self, message: &str) -> (Scalar, Scalar) {
        // 1. generate a random number k
        // let k = rand::thread_rng().gen_range(0..=255);
        let k = Scalar::new(100);
        // 2. calculate r = k * G
        let r = &k * &self.g;
        // 3. calculate public key pk = private_key * G
        let pk = &self.private_key * &self.g;
        // 4. calculate e = hash(r || pk || message)
        let e = hash(&r, &pk, message);
        println!("e: {}", e);
        // 5. calculate s = k + e * private_key
        let s = &k + (&e * &self.private_key);
        // 6. return signature (r, s)
        (r, s)
    }

    pub fn verify(&self, message: &str, signature: (Scalar, Scalar)) -> bool {
        // 1. get the signature
        let (r, s) = signature;
        // 2. get the public key
        let pk = &self.public_key;
        // 3. calculate e = hash(r || pk || message)
        let e = hash(&r, &pk, message);
        // 4. verify the signature: s * G = r + e * pk
        assert_eq!((s * &self.g), r + (e * pk));
        true
    }
}

// add test
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr() {
        let schnorr = Schnorr::new(Scalar::new(1));
        let signature = schnorr.sign("hello");
        assert!(schnorr.verify("hello", signature));
    }

    // Start Generation Here
    #[test]
    fn test_scalar_new() {
        let scalar = Scalar::new(65521);
        assert_eq!(scalar.value, 0); // 65521 % 65521 = 0
    }

    #[test]
    fn test_scalar_addition() {
        let a = Scalar::new(2);
        let b = Scalar::new(3);
        let c = a + b;
        assert_eq!(c.value, 5); // (2 + 3) % 65521 = 5
    }

    #[test]
    fn test_scalar_multiplication() {
        let a = Scalar::new(3);
        let b = Scalar::new(4);
        let c = a * b;
        assert_eq!(c.value, 12); // (3 * 4) % 65521 = 12
    }

    // #[test]
    // fn test_scalar_order() {
    //     // Order of the secp256k1 elliptic curve in hexadecimal
    //     const ORDER_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    //     let order = u256::from(ORDER_HEX.split_at(32));
    //     println!("{:?}", order);
    // }
}


