use sha2::{Sha256, Digest};
use rand::Rng;
use std::time::Instant;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint8, ClientKey, FheBool};

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
    let start_add = Instant::now();
    let encrypted_res_add = &encrypted_a + &encrypted_b; // 1344 * 5
    let end_add = Instant::now();
    println!("Time taken for add: {:?}", end_add.duration_since(start_add));
    let start_mul = Instant::now();
    let encrypted_res_mul = &encrypted_a * &encrypted_b; // 1344 * 5
    let end_mul = Instant::now();
    println!("Time taken for mul: {:?}", end_mul.duration_since(start_mul));
    let start_shift = Instant::now();
    let shifted_a = &encrypted_a >> &encrypted_b; // 6720 >> 5
    let end_shift = Instant::now();
    println!("Time taken for shift: {:?}", end_shift.duration_since(start_shift));
    let start_cast = Instant::now();
    let casted_a: FheUint8 = shifted_a.cast_into(); // Cast to u8
    let end_cast = Instant::now();
    println!("Time taken for cast: {:?}", end_cast.duration_since(start_cast));
    let start_min = Instant::now();
    let encrypted_res_min = &casted_a.min(&encrypted_c); // min(210, 7)
    let end_min = Instant::now();
    println!("Time taken for min: {:?}", end_min.duration_since(start_min));
    let start_and = Instant::now();
    let encrypted_res = encrypted_res_min & 1_u8; // 7 & 1
    let end_and = Instant::now();
    println!("Time taken for and: {:?}", end_and.duration_since(start_and));

    // Keep original encrypted_a for later use
    let start_div = Instant::now();
    let encrypted_res_div = &encrypted_a / &encrypted_b; // 1344 / 5 = 268
    let end_div = Instant::now();
    println!("Time taken for div: {:?}", end_div.duration_since(start_div));

    // Decrypting on the client side:
    let start_decrypt = Instant::now();
    let clear_res: u8 = encrypted_res.decrypt(&client_key);
    let end_decrypt = Instant::now();
    println!("Time taken for decrypt: {:?}", end_decrypt.duration_since(start_decrypt));
    assert_eq!(clear_res, 1_u8);

    println!("Decrypted result: {}", clear_res);

    // Get division result
    let start_decrypt_div = Instant::now();
    let decrypted_div: u32 = encrypted_res_div.decrypt(&client_key);
    let end_decrypt_div = Instant::now();
    println!("Time taken for decrypt div: {:?}", end_decrypt_div.duration_since(start_decrypt_div));
    let clear_div = clear_a / clear_b;
    println!("Clear division result: {}", clear_div);
    println!("Decrypted division result: {}", decrypted_div);
    assert_eq!(decrypted_div, clear_div);
    // Compare with float division
    let start_float_div = Instant::now();
    let clear_div_f = clear_a as f32 / clear_b as f32;
    let end_float_div = Instant::now();
    println!("Time taken for float div: {:?}", end_float_div.duration_since(start_float_div));
    println!("Float division result: {}", clear_div_f);
    // Time taken for add: 83.633613486s
    // Time taken for mul: 722.108276373s
    // Time taken for shift: 330.283779171s
    // Time taken for cast: 46.829µs
    // Time taken for min: 38.78299005s
    // Time taken for and: 8.523563505s
    // Time taken for div: 4211.997434488s
    // Time taken for decrypt: 365.956µs
    // Decrypted result: 1
    // Time taken for decrypt div: 912.233µs
    // Clear division result: 268
    // Decrypted division result: 268
    // Time taken for float div: 78ns
    // Float division result: 268.8
    Ok(())
}


