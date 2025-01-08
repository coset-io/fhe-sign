
mod sha256_bool;
mod sha256;
mod perf_test;
mod schnorr;
mod sha256_fhe_test;

pub mod rayon_wrapper {
    pub use rayon::iter::{IntoParallelIterator, ParallelIterator};
}

pub use rayon_wrapper::*;

#[doc(hidden)]
#[macro_export]
pub fn __requires_sendable_closure<R, F: FnOnce() -> R + Send>(x: F) -> F {
    x
}

use tfhe::prelude::*;
use sha2::{Sha256, Digest};
use rand::Rng;
use std::time::Instant;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, ClientKey, FheBool, CompressedServerKey};

use tfhe::boolean::prelude::{ClientKey as ClientKeyBool, Ciphertext, gen_keys};
use crate::sha256_bool::{pad_sha256_input, bools_to_hex, sha256_fhe as sha256_fhe_bool};
use crate::sha256::{sha256_fhe, encrypt_data, decrypt_hash};
use crate::schnorr::{Schnorr, hash};


// fn hash(message: &str) -> u32 {
//     let mut hasher_input = Vec::new();
//     hasher_input.extend(message.as_bytes());
//     let mut hasher = Sha256::new();
//     hasher.update(&hasher_input);
//     let hash_result = hasher.finalize();
//     // todo: only take the first 2 bytes
//     u32::from_be_bytes(hash_result[..4].try_into().expect("Hash output too short")) & 0xFFFF
// }

fn hash_encrypted(encrypted_input: Vec<tfhe::FheUint<tfhe::FheUint32Id>>, client_key: Option<&ClientKey>) -> Result<FheUint32, Box<dyn std::error::Error>> {
    let encrypted_hash = sha256_fhe(encrypted_input);
    let encrypted_hash_clone = encrypted_hash.clone();
    let decrypted_hash = decrypt_hash(encrypted_hash_clone, client_key);
    let hex_string = decrypted_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    println!("{}", hex_string);
    let sum = encrypted_hash.iter().cloned().sum::<FheUint32>();
    Ok(sum)
}

struct FheSchnorr {
    private_key: u32,
    public_key: u32,
    g: u32,
    private_key_encrypted: FheUint32,
    public_key_encrypted: FheUint32,
}

// implement fhe schnorr protocol, all operations use fhe
impl FheSchnorr {
    fn new(private_key: u32, client_key: &ClientKey) -> Result<Self, Box<dyn std::error::Error>> {
        let g: u32 = 2; // Define G
        let public_key = private_key * g;
        let private_key_encrypted = FheUint32::try_encrypt(private_key, client_key)?;
        let public_key_encrypted = FheUint32::try_encrypt(public_key, client_key)?;
        Ok(Self {
            private_key,
            public_key,
            g,
            private_key_encrypted,
            public_key_encrypted,
        })
    }

    fn sign(&self, message: &str, client_key: &ClientKey) -> Result<(u32, u64), Box<dyn std::error::Error>> {
        // 1. generate a random number k
        let k = rand::thread_rng().gen_range(0..=255);
        let k_encrypted = FheUint32::try_encrypt(k, client_key)?;
        // 2. calculate r = k * G
        let r = k * self.g;
        // 3. calculate public key pk = private_key * G
        let pk = self.private_key * self.g;
        // 4. calculate e = hash(r || pk || message)
        // let message_hash = hash(message);
        let e = hash(r, pk, message);
        let e_encrypted = FheUint32::try_encrypt(e, client_key)?;
        // let message_hash_encrypted = FheUint32::try_encrypt(message_hash, &self.client_key)?;

        // let input = r.to_string() + &pk.to_string() + &message_hash.to_string();
        // let buf = input.as_bytes().to_vec();
        // let encrypted_input = encrypt_data(buf, Some(client_key));
        // let e_encrypted = hash_encrypted(encrypted_input, Some(client_key)).unwrap();
        println!("e_encrypted finished");
        // 5. calculate s = k + e * private_key
        let s_encrypted = k_encrypted + e_encrypted * self.private_key_encrypted.clone();
        println!("s_encrypted finished");
        let s = s_encrypted.decrypt(client_key);
        println!("s finished");
        // 6. return signature (r, s)
        Ok((r, s))
    }

    // verify: s * g ?= r + e * pk
    // s_encrypted * g ?= r + e_encrypted * pk_encrypted
    // equals to: s_encrypted * g ?= k * g + e_encrypted * private_key_encrypted * g
    // we only need to check if s_encrypted == k + private_key_encrypted
    // fn verify(&self, message: &str, signature: (u32, u32), client_key: &ClientKey) -> Result<FheBool, Box<dyn std::error::Error>> {
    //     let (r, s) = signature;
    //     let pk = self.public_key_encrypted.clone();

    //     let message_hash = hash(message);
    //     let input = r.to_string() + &self.public_key.to_string() + &message_hash.to_string();
    //     let buf = input.as_bytes().to_vec();
    //     let encrypted_input = encrypt_data(buf, Some(client_key));
    //     let e_encrypted = hash_encrypted(encrypted_input, Some(client_key)).unwrap();

    //     let s_g = s * self.g;
    //     let r_e_pk = r + e_encrypted * self.public_key;
    //     Ok(s_g == r_e_pk)
    // }
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

        let schnorr = Schnorr::new(private_key);
        let signature_original = schnorr.sign(message);
        let result = schnorr.verify(message, signature_original);
        assert!(result);

        println!("original signature: {:?}", signature_original);

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
        assert_eq!(signature_original.0, signature_fhe.0);
        assert_eq!(signature_original.1, signature_fhe.1);

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


