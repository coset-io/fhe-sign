use sha2::{Sha256, Digest};
use rand::Rng;

struct Schnorr {
    private_key: u64,
    public_key: u64,
    g: u64,
}

impl Schnorr {
    fn new(private_key: u64) -> Self {
        let g: u64 = 2; // Define G
        let public_key = private_key * g;
        Self { private_key, public_key, g }
    }

    fn hash(&self, r: u64, pk: u64, message: &str) -> u64 {
        let mut hasher_input = Vec::new();
        hasher_input.extend(&r.to_be_bytes());
        hasher_input.extend(&pk.to_be_bytes());
        hasher_input.extend(message.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(&hasher_input);
        let hash_result = hasher.finalize();
        let result_u32 = u32::from_be_bytes(hash_result[..4].try_into().expect("Hash output too short"));
        result_u32 as u64
    }

    fn sign(&self, message: &str) -> (u64, u64) {
        // 1. generate a random number k
        let k = rand::thread_rng().gen_range(0..=255);
        // 2. calculate r = k * G
        let r = k * self.g;
        // 3. calculate public key pk = private_key * G
        let pk = self.private_key * self.g;
        // 4. calculate e = hash(r || pk || message)
        let e = self.hash(r, pk, message);
        println!("e: {}", e);
        // 5. calculate s = k + e * private_key
        let s = k + e * self.private_key;
        // 6. return signature (r, s)
        (r, s)
    }

    fn verify(&self, message: &str, signature: (u64, u64)) -> bool {
        // 1. get the signature
        let (r, s) = signature;
        // 2. get the public key
        let pk = self.public_key;
        // 3. calculate e = hash(r || pk || message)
        let e = self.hash(r, pk, message);
        // 4. verify the signature: s * G = r + e * pk
        assert_eq!(s * self.g, r + e * pk);
        true
    }
}

// add test
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr() {
        let schnorr = Schnorr::new(1);
        let signature = schnorr.sign("hello");
        assert!(schnorr.verify("hello", signature));
    }
}


