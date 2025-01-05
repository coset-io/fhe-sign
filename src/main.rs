use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint8};
use sha2::{Sha256, Digest};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic configuration to use homomorphic integers
    let config = ConfigBuilder::default().build();

    // Key generation
    let (client_key, server_keys) = generate_keys(config);

    let clear_a = 1344u32;
    let clear_b = 5u32;
    let clear_c = 7u8;

    // Encrypting the input data using the (private) client_key
    let encrypted_a = FheUint32::try_encrypt(clear_a, &client_key)?;
    let encrypted_b = FheUint32::try_encrypt(clear_b, &client_key)?;
    let encrypted_c = FheUint8::try_encrypt(clear_c, &client_key)?;

    // On the server side:
    set_server_key(server_keys);

    // Perform homomorphic operations
    let encrypted_res_mul = &encrypted_a * &encrypted_b; // 1344 * 5
    let shifted_a = &encrypted_res_mul >> &encrypted_b; // 6720 >> 5
    let casted_a: FheUint8 = shifted_a.cast_into(); // Cast to u8
    let encrypted_res_min = &casted_a.min(&encrypted_c); // min(210, 7)
    let encrypted_res = encrypted_res_min & 1_u8; // 7 & 1

    // Keep original encrypted_a for later use
    let encrypted_res_div = &encrypted_a / &encrypted_b; // 1344 / 5 = 268

    // Decrypting on the client side:
    let clear_res: u8 = encrypted_res.decrypt(&client_key);
    assert_eq!(clear_res, 1_u8);

    println!("Decrypted result: {}", clear_res);

    // Get division result
    let decrypted_div: u32 = encrypted_res_div.decrypt(&client_key);
    let clear_div = clear_a / clear_b;
    println!("Clear division result: {}", clear_div);
    println!("Decrypted division result: {}", decrypted_div);
    assert_eq!(decrypted_div, clear_div);
    // Compare with float division
    let clear_div_f = clear_a as f32 / clear_b as f32;
    println!("Float division result: {}", clear_div_f);

    Ok(())
}

// implement schnorr protocol
struct Schnorr {
    private_key: u32,
    public_key: u32,
    G: u32,
}

impl Schnorr {
    fn new(private_key: u32) -> Self {
        let G: u32 = 2; // Define G
        let public_key = private_key * G;
        Self { private_key, public_key, G }
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
        // let k = rand::thread_rng().gen_range(0..=255);
        let k = 2;
        // 2. calculate r = k * G
        let r = k * self.G;
        // 3. calculate public key pk = private_key * G
        let pk = self.private_key * self.G;
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
        assert_eq!(s * self.G, r + e * pk);
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
