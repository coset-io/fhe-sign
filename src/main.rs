use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint8};

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