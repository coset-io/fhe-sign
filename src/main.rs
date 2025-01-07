use sha2::{Sha256, Digest};
use rand::Rng;
use std::time::Instant;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint8, ClientKey, FheBool};

mod sha256_bool;

use crate::sha256_bool::{pad_sha256_input, bools_to_hex, sha256_fhe};
use std::io;
use tfhe::boolean::prelude::{ClientKey as ClientKeyBool, Ciphertext, gen_keys};

fn main() {
    // let matches = Command::new("Homomorphic sha256")
    //     .arg(
    //         Arg::new("ladner_fischer")
    //             .long("ladner-fischer")
    //             .help("Use the Ladner Fischer parallel prefix algorithm for additions")
    //             .action(ArgAction::SetTrue),
    //     )
    //     .get_matches();

    // If set using the command line flag "--ladner-fischer" this algorithm will be used in
    // additions
    let ladner_fischer: bool = false;

    // INTRODUCE INPUT FROM STDIN

    // let mut input = String::new();
    println!("Write input to hash:");

    // io::stdin()
    //     .read_line(&mut input)
    //     .expect("Failed to read line");
    let mut input = "Hello World".to_string();
    input = input.trim_end_matches('\n').to_string();

    println!("You entered: \"{}\"", input);

    // CLIENT PADS DATA AND ENCRYPTS IT

    let (ck, sk) = gen_keys();

    let padded_input = pad_sha256_input(&input);
    let encrypted_input = encrypt_bools(&padded_input, &ck);

    // SERVER COMPUTES OVER THE ENCRYPTED PADDED DATA

    println!("Computing the hash");
    let encrypted_output = sha256_fhe(encrypted_input, ladner_fischer, &sk);

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
    private_key: FheUint32,
    public_key: FheUint32,
    g: FheUint32,
    client_key: ClientKey,
}

// implement fhe schnorr protocol, all operations use fhe
impl FheSchnorr {
    fn new(private_key_orig: u32, client_key: &ClientKey) -> Result<Self, Box<dyn std::error::Error>> {
        let g_orig: u32 = 2; // Define G
        let public_key_orig = private_key_orig * g_orig;
        let private_key = FheUint32::try_encrypt(private_key_orig, client_key)?;
        let public_key = FheUint32::try_encrypt(public_key_orig, client_key)?;
        let g = FheUint32::try_encrypt(g_orig, client_key)?;
        Ok(Self { private_key, public_key, g, client_key: client_key.clone() })
    }

    fn hash(&self, message: &str) -> u32 {
        let mut hasher_input = Vec::new();
        hasher_input.extend(message.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(&hasher_input);
        let hash_result = hasher.finalize();
        u32::from_be_bytes(hash_result[..4].try_into().expect("Hash output too short")) & 0xFFFF
    }

    // TODO: implement hash function
    fn hash_encrypted(&self, r: FheUint32, pk: FheUint32, message: FheUint32) -> FheUint32 {
        // let mut hasher_input = Vec::new();
        // Assuming FheUint32 has a method to_bytes() that returns a byte array
        // hasher_input.extend(&r.to_bytes());
        // hasher_input.extend(&pk.to_bytes());
        // hasher_input.extend(message.as_bytes());
        // let mut hasher = Sha256::new();
        // hasher.update(&hasher_input);
        // let hash_result = hasher.finalize();
        // FheUint32::from_be_bytes(hash_result[..4].try_into().expect("Hash output too short")) & 0xFFFF
        // workaround: just concatenate all encrypted values
        r + pk + message
    }

    fn sign(&self, message: &str) -> Result<(FheUint32, FheUint32), Box<dyn std::error::Error>> {
        // 1. generate a random number k
        let k = rand::thread_rng().gen_range(0..=255);
        // 2. calculate r = k * G
        let r = k * self.g.clone();
        // 3. calculate public key pk = private_key * G
        let pk = self.private_key.clone() * self.g.clone();
        // 4. calculate e = hash(r || pk || message)
        let message_hash = self.hash(message);
        let message_hash_encrypted = FheUint32::try_encrypt(message_hash, &self.client_key)?;
        // does all these values need to be encrypted?
        let e = self.hash_encrypted(r.clone(), pk, message_hash_encrypted);
        // 5. calculate s = k + e * private_key
        let s = k + e * self.private_key.clone();
        // 6. return signature (r, s)
        Ok((r, s))
    }

    fn verify(&self, message: &str, signature: (FheUint32, FheUint32)) -> Result<FheBool, Box<dyn std::error::Error>> {
        let (r, s) = signature;
        let pk = self.public_key.clone();
        let message_hash = self.hash(message);
        let message_hash_encrypted = FheUint32::try_encrypt(message_hash, &self.client_key)?;
        let e = self.hash_encrypted(r.clone(), pk.clone(), message_hash_encrypted.clone());
        let s_g = s.clone() * self.g.clone();
        let r_e_pk = r.clone() + e * pk.clone();
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
        println!("start");
        let config = ConfigBuilder::default().build();
        println!("config");
        let (client_key, server_keys) = generate_keys(config);
        println!("generate_keys");
        set_server_key(server_keys);
        println!("server keys");
        let fhe_schnorr = FheSchnorr::new(1, &client_key).unwrap();
        println!("fhe schnorr");
        let signature = fhe_schnorr.sign("hello").unwrap();
        println!("signature");
        let result = fhe_schnorr.verify("hello", signature).unwrap();
        println!("result");
        let decrypted_result = result.decrypt(&client_key);
        println!("decrypted result");
        assert!(decrypted_result);
        println!("end");
    }
}


