mod perf_test;
mod schnorr;
mod schnorr_btc;
mod scalar;
mod secp256k1;

use tfhe::prelude::*;
use sha2::{Sha256, Digest};
use rand::Rng;
use std::time::Instant;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint64, ClientKey, FheBool, CompressedServerKey};
use crate::schnorr::Schnorr;

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

struct FheSchnorr {
    private_key_encrypted: FheUint64,
    public_key: u32,
    g: u32,
}

// implement fhe schnorr protocol, all operations use fhe
impl FheSchnorr {
    fn new(private_key: u32, client_key: &ClientKey) -> Result<Self, Box<dyn std::error::Error>> {
        let g: u32 = 2; // Define G
        let public_key = private_key * g;
        let private_key_encrypted = FheUint64::try_encrypt(private_key, client_key)?;
        Ok(Self {
            private_key_encrypted,
            public_key,
            g,
        })
    }

    fn sign(&self, message: &str, client_key: &ClientKey) -> Result<(u32, u64), Box<dyn std::error::Error>> {
        // 1. generate a random number k
        // let k = rand::thread_rng().gen_range(0..=255);
        let k = 100;
        let start = Instant::now();
        let k_encrypted = FheUint64::try_encrypt(k, client_key)?;
        let end = Instant::now();
        println!("time taken for encrypt: {:?}", end.duration_since(start));
        // 2. calculate r = k * G
        let r = k * self.g;
        // 3. calculate public key pk = private_key * G
        // let pk = self.private_key * self.g;
        let pk = self.public_key;
        // 4. calculate e = hash(r || pk || message)
        let e = hash(r, pk, message);
        let start = Instant::now();
        let e_encrypted = FheUint64::try_encrypt(e, client_key)?;
        let end = Instant::now();
        println!("time taken for encrypt: {:?}", end.duration_since(start));
        // 5. calculate s = k + e * private_key
        let s_encrypted = k_encrypted + e_encrypted * self.private_key_encrypted.clone();
        println!("s_encrypted finished");
        let start = Instant::now();
        let s = s_encrypted.decrypt(client_key);
        let end = Instant::now();
        println!("time taken for decrypt: {:?}", end.duration_since(start));
        // 6. return signature (r, s)
        Ok((r, s))
    }

    // since we already got the decrypted signature, we can directly verify it
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
    use super::*;
    #[test]
    fn test_fhe_schnorr() {
        let total_timer = Instant::now();
        let private_key = 2025010716;
        let message = "Hello World";

        // let schnorr = Schnorr::new(private_key);
        // let signature_original = schnorr.sign(message);
        // let result = schnorr.verify(message, signature_original);
        // assert!(result);

        // println!("original signature: {:?}", signature_original);

        println!("start");
        let config = ConfigBuilder::default().build();
        println!("config");
        let (client_key, server_keys) = generate_keys(config);
        println!("generate_keys");
        set_server_key(server_keys);
        println!("server keys");

        let fhe_schnorr = FheSchnorr::new(private_key, &client_key).unwrap();
        println!("fhe schnorr");

        let start = Instant::now();
        let signature_fhe = fhe_schnorr.sign(message, &client_key).unwrap();
        let end = Instant::now();
        println!("signature_fhe: {:?}", signature_fhe);
        println!("time taken for sign: {:?}", end.duration_since(start));
        // do the check
        // assert_eq!(signature_original.0, signature_fhe.0);
        // assert_eq!(signature_original.1, signature_fhe.1);

        // let start = Instant::now();
        // let result = fhe_schnorr.verify(message, signature_fhe);
        // let end = Instant::now();
        // println!("time taken for verify: {:?}", end.duration_since(start));

        // let start = Instant::now();
        // let decrypted_result = result.decrypt(&client_key);
        // let end = Instant::now();
        // println!("time taken for decrypt: {:?}", end.duration_since(start));

        // assert!(decrypted_result);

        println!("end");
        println!("Total time: {:?}", total_timer.elapsed());
    }
}


