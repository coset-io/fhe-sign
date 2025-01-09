use k256::schnorr::{
    signature::{Signer, Verifier},
    SigningKey, VerifyingKey
};
use rand_core::OsRng; // requires 'getrandom' feature

use schnorr_fun::{
    fun::{marker::Public,nonce, Scalar},
    Schnorr,
    Message,
    Signature
};
use sha2::Sha256;
use rand::rngs::ThreadRng;
use hex;

pub fn schnorr_btc() {
    // Signing
    let signing_key = SigningKey::random(&mut OsRng); // serialize with `.to_bytes()`
    let verifying_key_bytes = signing_key.verifying_key().to_bytes(); // 32-bytes
    println!("verifying_key_bytes: {:?}", verifying_key_bytes);

    let message = b"Schnorr signatures prove knowledge of a secret in the random oracle model";
    let signature = signing_key.sign(message); // returns `k256::schnorr::Signature`
    println!("signature: {:?}", signature);

    // Verification
    let verifying_key = VerifyingKey::from_bytes(verifying_key_bytes.as_slice()).unwrap();
    verifying_key.verify(message, &signature).unwrap();

    println!("Schnorr signature created and verified successfully.");
}

pub fn schnorr_fun() {
    // Use synthetic nonces
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone());
    // Generate your public/private key-pair
    // todo: here we do not use random number for testing
    let keypair = schnorr.new_keypair(Scalar::one());
    // Sign a variable length message
    let message = Message::<Public>::plain("the-times-of-london", b"Chancellor on brink of second bailout for banks");
    // Sign the message with our keypair
    let signature = schnorr.sign(&keypair, message);
    println!("signature: {:?}", signature);
    // todo: make the check work by not using random number
    let expected_signature = Signature::<Public>::from_bytes(
        hex::decode("373ade08b7b92724082cd14a06567a324aa00107a910e5408f42aaa642a4128b393c48d01d5b17fcda0d4b043e62a7a70cc25d91df9e54d5bbb9ce3b61472f16")
            .unwrap()
            .try_into()
            .unwrap()
    ).unwrap();
    assert_eq!(signature, expected_signature);

    // Get the verifier's key
    let verification_key = keypair.public_key();
    // Check it's valid 🍿
    assert!(schnorr.verify(&verification_key, message, &signature));

    println!("Schnorr signature created and verified successfully.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr() {
        schnorr_btc();
        schnorr_fun();
    }
}
