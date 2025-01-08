
pub mod rayon_wrapper {
    pub use rayon::iter::{IntoParallelIterator, ParallelIterator};
}

pub use rayon_wrapper::*;

#[doc(hidden)]
#[macro_export]
pub fn __requires_sendable_closure<R, F: FnOnce() -> R + Send>(x: F) -> F {
    x
}

use sha2::{Sha256, Digest};
use rand::Rng;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint8, ClientKey, FheBool, CompressedServerKey};

use tfhe::boolean::prelude::{ClientKey as ClientKeyBool, Ciphertext, gen_keys};
use crate::sha256_bool::{pad_sha256_input, bools_to_hex, sha256_fhe as sha256_fhe_bool};
use crate::sha256::{sha256_fhe, encrypt_data, decrypt_hash};
use std::io::{stdin, Read};

fn sha256_fhe_main(client_key: ClientKey) -> Result<(), std::io::Error> {
    let mut buf = vec![];
    stdin().read_to_end(&mut buf)?;
    println!("input: {}", String::from_utf8_lossy(&buf));

    let encrypted_input = encrypt_data(buf, Some(&client_key));

    let encrypted_hash = sha256_fhe(encrypted_input);
    let decrypted_hash = decrypt_hash(encrypted_hash, Some(&client_key));
    // println!("{}", hex::encode(decrypted_hash));
    let hex_string = decrypted_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    println!("{}", hex_string);

    Ok(())
}

fn sha256_fhe_bool_main(input: String) {
    let ladner_fischer: bool = false;

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

mod tests {
    use super::*;

    #[test]
    fn test_sha256_fhe_main() {
        let config = ConfigBuilder::default().build();
        let client_key = ClientKey::generate(config);
        let csks = CompressedServerKey::new(&client_key);
        let server_key = csks.decompress();
        set_server_key(server_key);

        sha256_fhe_main(client_key).unwrap();
        // sha256_fhe_bool_main();
    }
}