use pqcrypto_dilithium::dilithium2::*;
use pqcrypto_traits::sign::{
    PublicKey as PublicKeyTrait,
    SecretKey as SecretKeyTrait,
    DetachedSignature as DetachedSignatureTrait,
    SignedMessage as SignedMessageTrait,
};
use base64::{engine::general_purpose, Engine};


/// A quantum-safe public/secret keypair
#[derive(Debug, Clone)]
pub struct QuantumKeypair {
    pub public_key: String,  // Base64-encoded
    pub secret_key: String,  // Base64-encoded
}

/// A quantum-safe signature
#[derive(Debug, Clone)]
pub struct QuantumSignature {
    pub signature: String, // Base64-encoded
}

/// Allow signing directly from the QuantumKeypair struct
impl QuantumKeypair {
    pub fn sign(&self, message: &[u8]) -> QuantumSignature {
        sign_message(&self.secret_key, message)
    }
}

/// Generate a fresh Dilithium2 keypair (quantum secure)
pub fn generate_dilithium_keypair() -> QuantumKeypair {
    let (public_key, secret_key) = keypair();
    QuantumKeypair {
        public_key: general_purpose::STANDARD.encode(public_key.as_bytes()),
        secret_key: general_purpose::STANDARD.encode(secret_key.as_bytes()),
    }
}

/// Sign a message (the hash) with a secret key
pub fn sign_message(secret_key_b64: &str, message: &[u8]) -> QuantumSignature {
    let secret_key_bytes = general_purpose::STANDARD.decode(secret_key_b64)
        .expect("Invalid base64 encoding in secret key");
    let secret_key = SecretKey::from_bytes(&secret_key_bytes)
        .expect("Invalid secret key bytes");

    let signature = detached_sign(message, &secret_key);

    QuantumSignature {
        signature: general_purpose::STANDARD.encode(signature.as_bytes()),
    }
}

/// Verify a signature against a public key
pub fn verify_signature(public_key_b64: &str, message: &[u8], signature_b64: &str) -> Result<(), String> {
    let public_key_bytes = general_purpose::STANDARD.decode(public_key_b64)
        .map_err(|_| "Invalid base64 in public key".to_string())?;
    let signature_bytes = general_purpose::STANDARD.decode(signature_b64)
        .map_err(|_| "Invalid base64 in signature".to_string())?;

    let public_key = PublicKey::from_bytes(&public_key_bytes)
        .map_err(|_| "Invalid public key bytes".to_string())?;
    let detached_signature = DetachedSignature::from_bytes(&signature_bytes)
        .map_err(|_| "Invalid detached signature bytes".to_string())?;

    // Manually concatenate signature + message
    let mut signed_message_bytes = detached_signature.as_bytes().to_vec();
    signed_message_bytes.extend_from_slice(message);

    let signed_message = SignedMessage::from_bytes(&signed_message_bytes)
        .map_err(|_| "Invalid signed message format".to_string())?;

    // Now you can call open!
    open(&signed_message, &public_key)
        .map(|_| ())
        .map_err(|_| "Signature verification failed".to_string())
}
