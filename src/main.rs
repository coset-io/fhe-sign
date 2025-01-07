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
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint8, ClientKey, FheBool, CompressedServerKey};

mod sha256_bool;
mod sha256;

use tfhe::boolean::prelude::{ClientKey as ClientKeyBool, Ciphertext, gen_keys};
use crate::sha256_bool::{pad_sha256_input, bools_to_hex, sha256_fhe as sha256_fhe_bool};
use crate::sha256::{sha256_fhe, encrypt_data, decrypt_hash};
use std::io::{stdin, Read};

fn sha256_fhe_main() -> Result<(), std::io::Error> {

    let config = ConfigBuilder::default().build();

    let client_key = ClientKey::generate(config);
    let csks = CompressedServerKey::new(&client_key);

    let server_key = csks.decompress();
    set_server_key(server_key);

    println!("key gen end");

    let mut buf = vec![];
    stdin().read_to_end(&mut buf)?;
    println!("input: {}", String::from_utf8_lossy(&buf));

    let client_key = Some(client_key);
    let encrypted_input = encrypt_data(buf, client_key.as_ref());

    let encrypted_hash = sha256_fhe(encrypted_input);
    let decrypted_hash = decrypt_hash(encrypted_hash, client_key.as_ref());
    // println!("{}", hex::encode(decrypted_hash));
    let hex_string = decrypted_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    println!("{}", hex_string);

    Ok(())
}

fn sha256_fhe_bool_main(input: String) {

    let ladner_fischer: bool = false;

    // INTRODUCE INPUT FROM STDIN

    // let mut input = String::new();
    println!("Write input to hash:");

    // io::stdin()
    //     .read_line(&mut input)
    //     .expect("Failed to read line");
    // let mut input = "Hello World".to_string();
    // input = input.trim_end_matches('\n').to_string();

    println!("You entered: \"{}\"", input);

    // CLIENT PADS DATA AND ENCRYPTS IT

    let (ck, sk) = gen_keys();

    let padded_input = pad_sha256_input(&input);
    let encrypted_input = encrypt_bools(&padded_input, &ck);

    // SERVER COMPUTES OVER THE ENCRYPTED PADDED DATA

    println!("Computing the hash");
    let encrypted_output = sha256_fhe_bool(encrypted_input, ladner_fischer, &sk);

    // CLIENT DECRYPTS THE OUTPUT

    let output = decrypt_bools(&encrypted_output, &ck);
    let outhex = bools_to_hex(output);

    println!("outhex: {}", outhex);
}

fn encrypt_bools(bools: &Vec<bool>, ck: &ClientKeyBool) -> Vec<Ciphertext> {
    let mut ciphertext = vec![];

    for bool in bools {
        ciphertext.push(ck.encrypt(*bool));
    }
    ciphertext
}

fn decrypt_bools(ciphertext: &Vec<Ciphertext>, ck: &ClientKeyBool) -> Vec<bool> {
    let mut bools = vec![];

    for cipher in ciphertext {
        bools.push(ck.decrypt(cipher));
    }
    bools
}

fn main() {
    sha256_fhe_main().unwrap();
    // sha256_fhe_bool_main();
}

// implement schnorr protocol
struct Schnorr {
    private_key: u32,
    public_key: u32,
    g: u32,
}

impl Schnorr {
    fn new(private_key: u32) -> Self {
        let g: u32 = 2; // Define G
        let public_key = private_key * g;
        Self { private_key, public_key, g }
    }

    fn hash(&self, r: u32, pk: u32, message: &str) -> u32 {
        let mut hasher_input = Vec::new();
        hasher_input.extend(&r.to_be_bytes());
        hasher_input.extend(&pk.to_be_bytes());
        hasher_input.extend(message.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(&hasher_input);
        let hash_result = hasher.finalize();
        u32::from_be_bytes(hash_result[..4].try_into().expect("Hash output too short")) & 0xFFFF
    }

    fn sign(&self, message: &str) -> (u32, u32) {
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

    fn verify(&self, message: &str, signature: (u32, u32)) -> bool {
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

struct FheSchnorr {
    private_key: u32,
    public_key: u32,
    g: u32,
    private_key_encrypted: FheUint32,
    public_key_encrypted: FheUint32,
    g_encrypted: FheUint32,
    client_key: ClientKey,
}

// implement fhe schnorr protocol, all operations use fhe
impl FheSchnorr {
    fn new(private_key: u32, client_key: &ClientKey) -> Result<Self, Box<dyn std::error::Error>> {
        let g: u32 = 2; // Define G
        let public_key = private_key * g;
        let private_key_encrypted = FheUint32::try_encrypt(private_key, client_key)?;
        let public_key_encrypted = FheUint32::try_encrypt(public_key, client_key)?;
        let g_encrypted = FheUint32::try_encrypt(g, client_key)?;
        Ok(Self {
            private_key,
            public_key,
            g,
            private_key_encrypted,
            public_key_encrypted,
            g_encrypted,
            client_key: client_key.clone(),
        })
    }

    fn hash(&self, message: &str) -> u32 {
        let mut hasher_input = Vec::new();
        hasher_input.extend(message.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(&hasher_input);
        let hash_result = hasher.finalize();
        // only take the first 2 bytes
        u32::from_be_bytes(hash_result[..4].try_into().expect("Hash output too short")) & 0xFFFF
    }


    fn hash_encrypted(&self, encrypted_input: Vec<tfhe::FheUint<tfhe::FheUint32Id>>, client_key: Option<&ClientKey>) -> Result<FheUint32, Box<dyn std::error::Error>> {
        let encrypted_hash = sha256_fhe(encrypted_input);
        let encrypted_hash_clone = encrypted_hash.clone();
        let decrypted_hash = decrypt_hash(encrypted_hash_clone, client_key);
        let hex_string = decrypted_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        println!("{}", hex_string);
        let sum = encrypted_hash.iter().cloned().sum::<FheUint32>();
        Ok(sum)
    }

    // TODO: implement hash function
    fn hash_encrypted_bool(&self, input_str: String) -> Result<Vec<Ciphertext>, Box<dyn std::error::Error>> {
        let ladner_fischer: bool = false;

        // INTRODUCE INPUT FROM STDIN

        // let mut input = String::new();
        println!("Write input to hash:");

        // io::stdin()
        //     .read_line(&mut input)
        //     .expect("Failed to read line");
        let input = input_str.trim_end_matches('\n').to_string();

        println!("You entered: \"{}\"", input);

        // CLIENT PADS DATA AND ENCRYPTS IT

        let (ck, sk) = gen_keys();

        let padded_input = pad_sha256_input(&input);
        let encrypted_input = encrypt_bools(&padded_input, &ck);

        // SERVER COMPUTES OVER THE ENCRYPTED PADDED DATA

        println!("Computing the hash");
        let encrypted_output = sha256_fhe_bool(encrypted_input, ladner_fischer, &sk);

        // CLIENT DECRYPTS THE OUTPUT

        let output = decrypt_bools(&encrypted_output, &ck);
        let outhex = bools_to_hex(output);

        println!("outhex: {}", outhex);

        Ok(encrypted_output)
    }

    fn sign(&self, message: &str) -> Result<(u32, FheUint32), Box<dyn std::error::Error>> {
        // 1. generate a random number k
        let k = rand::thread_rng().gen_range(0..=255);
        // 2. calculate r = k * G
        let r = k * self.g;
        // 3. calculate public key pk = private_key * G
        let pk = self.private_key * self.g;
        // 4. calculate e = hash(r || pk || message)
        let message_hash = self.hash(message);
        // let message_hash_encrypted = FheUint32::try_encrypt(message_hash, &self.client_key)?;

        let config = ConfigBuilder::default().build();
        let client_key = ClientKey::generate(config);
        let csks = CompressedServerKey::new(&client_key);
        let server_key = csks.decompress();
        set_server_key(server_key);
        println!("key gen end");

        let input = r.to_string() + &pk.to_string() + &message_hash.to_string();
        let buf = input.as_bytes().to_vec();
        let encrypted_input = encrypt_data(buf, Some(&self.client_key));
        let e_encrypted = self.hash_encrypted(encrypted_input, Some(&self.client_key)).unwrap();

        // 5. calculate s = k + e * private_key
        let s_encrypted = k + e_encrypted * self.private_key_encrypted.clone();
        // 6. return signature (r, s)
        Ok((r, s_encrypted))
    }

    fn verify(&self, message: &str, signature: (u32, FheUint32)) -> Result<FheBool, Box<dyn std::error::Error>> {
        // verify: s * g = r + e * pk
        // s_encrypted * g_encrypted = r_encrypted + e_encrypted * pk_encrypted
        let (r, s_encrypted) = signature;
        let pk = self.public_key_encrypted.clone();
        let message_hash = self.hash(message);
        let input = r.to_string() + &self.public_key.to_string() + &message_hash.to_string();
        let buf = input.as_bytes().to_vec();
        let encrypted_input = encrypt_data(buf, Some(&self.client_key));
        let e_encrypted = self.hash_encrypted(encrypted_input, Some(&self.client_key)).unwrap();

        let r_encrypted = FheUint32::try_encrypt(r, &self.client_key)?;

        let s_g = s_encrypted.clone() * self.g_encrypted.clone();
        let r_e_pk = r_encrypted.clone() + e_encrypted * pk.clone();
        Ok(s_g.eq(&r_e_pk))
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

    #[test]
    fn test_fhe_schnorr() {
        let private_key = 2025010716;
        let message = "Hello World";
        println!("start");
        let config = ConfigBuilder::default().build();
        println!("config");
        let (client_key, server_keys) = generate_keys(config);
        println!("generate_keys");
        set_server_key(server_keys);
        println!("server keys");
        let fhe_schnorr = FheSchnorr::new(private_key, &client_key).unwrap();
        println!("fhe schnorr");
        let signature = fhe_schnorr.sign(message).unwrap();
        println!("signature");
        let result = fhe_schnorr.verify(message, signature).unwrap();
        println!("result");
        let decrypted_result = result.decrypt(&client_key);
        println!("decrypted result");
        assert!(decrypted_result);
        println!("end");
    }
}


