# FHE-Sign: Fully Homomorphic Encryption Signature Library

A Rust implementation of cryptographic signing operations using Fully Homomorphic Encryption (FHE), with a focus on secp256k1 and Schnorr signatures currently. This project is only for educational purpose.

## Overview

This library provides implementations for:
- Secp256k1 elliptic curve operations
- Field arithmetic in prime fields
- Homomorphic operations on big integers
- Performance testing utilities
- Schnorr signature scheme

## Features

- **Secp256k1 Implementation**: Basic implementation of the secp256k1 elliptic curve, including point addition, doubling, and scalar multiplication.
- **Field Arithmetic**: Generic finite field arithmetic implementation for prime fields.
- **FHE Operations**: Homomorphic operations on encrypted integers using the TFHE library.
- **BigUint FHE**: Custom implementation for handling large encrypted integers.
- **Schnorr Signatures**: Implementation of the Schnorr signature scheme with both standard and FHE variants.
- **BIP340 Test Vectors**: Comprehensive test suite using official test vectors.

## Dependencies

```toml
[dependencies]
tfhe = { version = "*", features = ["boolean", "shortint", "integer", "seeder_unix"] }
sha2 = "0.10"
rand = "0.8"
hex = "0.4"
num-bigint = { version = "0.4", features = ["rand"] }
```

## Core Components

### 1. Field Operations (`field.rs`)
- Implementation of finite field arithmetic
- Support for addition, subtraction, multiplication, and division
- Modular arithmetic operations

### 2. Scalar Operations (`scalar.rs`)
- Scalar field arithmetic for secp256k1
- Conversion between different formats
- Basic arithmetic operations in the scalar field

### 3. Secp256k1 (`secp256k1.rs`)
- Basic elliptic curve implementation
- Point arithmetic (addition, doubling, multiplication)
- Generator point and curve parameters

### 4. BigUint FHE (`biguint.rs`)
- Homomorphic operations on large integers
- Support for basic arithmetic operations
- Conversion between encrypted and plain formats

### 5. Schnorr Signatures (`schnorr.rs`)
- Implementation of FHE-based Schnorr signature scheme
- BIP340-compatible implementation

### 6. Performance Testing (`perf_test.rs`)
- Benchmarking utilities for FHE operations
- Comparison of different operation timings

## Usage Examples

### Basic Schnorr Signature
```rust
let config = ConfigBuilder::default().build();
let (client_key, server_keys) = generate_keys(config);
set_server_key(server_keys);

// Test vector from BIP-340
let seckey_bytes = hex::decode("0000000000000000000000000000000000000000000000000000000000000003").unwrap();
let message = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
let aux_rand = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

let privkey = Scalar::new(BigUint::from_bytes_be(&seckey_bytes));
let privkey_fhe = BigUintFHE::new(privkey.value().clone(), &client_key).unwrap();
let pubkey = get_public_key_with_even_y(&privkey);

let schnorr = Schnorr::new();
let k0 = compute_nonce(&privkey.value(), &pubkey, &message, &aux_rand);
// sign with k0
let sig_with_k0 = schnorr.sign_with_k0(&message, &k0, &privkey).unwrap();
// sign fhe with k0
let sig_fhe_with_k0 = schnorr.sign_fhe_with_k0(&message, &k0, &privkey, &privkey_fhe, &client_key).unwrap();

assert_eq!(sig_with_k0.to_bytes(), sig_fhe_with_k0.to_bytes());
assert!(Schnorr::verify(&message, &pubkey.x.value().to_bytes_be(), &sig_with_k0.to_bytes()));
```

## Testing

The library includes test suites for all components:

```bash
cargo test
```

Special test vectors for Schnorr signatures are included in `tests/test_vectors.csv` corresponded to BIP-314 specification.

## Performance Considerations

FHE operations are computationally intensive. Here are some typical operation times:
- Addition: ~83 seconds
- Multiplication: ~722 seconds
- Shift operations: ~330 seconds
- Minimum operations: ~38 seconds

Testing hardware:
- System: MacOS
- CPU: 2.6 GHz 6-Core Intel Core i7
- Memory: 32 GB 2667 MHz DDR4

## License

MIT

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a new branch for your feature (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests to ensure everything works (`cargo test`)
5. Commit your changes (`git commit -m 'Add some amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Development Guidelines

- Write clear commit messages
- Add tests for new functionality
- Update documentation as needed
- Follow Rust coding standards and best practices
- Ensure all tests pass before submitting PR

### Reporting Issues

If you find a bug or have a feature request, please open an issue:

1. Use the GitHub issue tracker
2. Describe the bug or feature request in detail
3. Include relevant code examples if applicable
4. For bugs, include steps to reproduce
