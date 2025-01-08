use k256::schnorr::{
    signature::{Signer, Verifier},
    SigningKey, VerifyingKey
};
use rand_core::OsRng; // requires 'getrandom' feature

pub fn schnorr_btc() {
    // Signing
    let signing_key = SigningKey::random(&mut OsRng); // serialize with `.to_bytes()`
    let verifying_key_bytes = signing_key.verifying_key().to_bytes(); // 32-bytes

    let message = b"Schnorr signatures prove knowledge of a secret in the random oracle model";
    let signature = signing_key.sign(message); // returns `k256::schnorr::Signature`

    // Verification
    let verifying_key = VerifyingKey::from_bytes(verifying_key_bytes.as_slice()).unwrap();
    verifying_key.verify(message, &signature).unwrap();

    println!("Schnorr signature created and verified successfully.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_btc() {
        schnorr_btc();
    }
}
