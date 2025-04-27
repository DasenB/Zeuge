// lib.rs

use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{SecretKey, PublicKey, DetachedSignature};
use chrono::{DateTime, Utc};
use matrix_sdk::{Client, config::SyncSettings};
use matrix_sdk::ruma::{
    api::client::room::create_room::v3::{Request as CreateRoomRequest, RoomPreset},
    UserId,
};
use matrix_sdk::Room;
use secrecy::{ExposeSecret, SecretString};
use std::{sync::{Arc, Mutex}, collections::HashMap};
use tokio::sync::OnceCell;
use orion::aead;
use base64::{encode as b64_encode, decode as b64_decode};
use matrix_sdk::ruma::events::room::message::RoomMessageEventContent;
use matrix_sdk::ruma::user_id;
use serde::{Serialize, Deserialize};


const ENCRYPTED_VALIDATION: &str = "rPaIln/QW7vwQpLjtbeV4WGEAtdGTkWgZg4bFg2Zeoceak6HMPMbLuoGLUmAiIyahEiWb7hxt1glnkpb7B8h/Ng==";
const VALIDATION_PLAINTEXT: &str = "example plaintext value";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Keypair {
    pub public_key: String,
    pub encrypted_private_key: String,
    #[serde(skip_serializing)]
    pub decrypted_private_key: Option<String>,
    pub created_at: DateTime<Utc>,
}

static MASTER_KEY: OnceCell<SecretString> = OnceCell::const_new();

pub async fn request_master_key() -> SecretString {
    let mut store = Arc::new(Mutex::new(None::<SecretString>));
    send_matrix_message("🔐 Vault requires master key: http://localhost:3000/unseal").await;

    loop {
        {
            let lock = store.lock().unwrap();
            if let Some(ref key) = *lock {
                if verify_master_key(key.expose_secret().as_bytes()).await {
                    send_matrix_message("✅ Vault successfully unlocked with master key.").await;
                    return SecretString::new(key.expose_secret().to_string().into_boxed_str());
                } else {
                    send_matrix_message("❌ Invalid master key. Please try again: http://localhost:3000/unseal").await;
                    *store.lock().unwrap() = None;
                }
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

pub fn generate_keypair(master_key: &[u8]) -> Keypair {
    let (pk, sk) = dilithium3::keypair();
    let encrypted_sk = encrypt_symmetric(master_key, sk.as_bytes());

    Keypair {
        public_key: b64_encode(pk.as_bytes()),
        encrypted_private_key: b64_encode(&encrypted_sk),
        decrypted_private_key: None,
        created_at: Utc::now(),
    }
}

pub fn decrypt_keypairs(master_key: &[u8], keypairs: &mut [Keypair]) {
    for kp in keypairs.iter_mut() {
        if kp.decrypted_private_key.is_none() {
            if let Ok(encrypted_bytes) = b64_decode(&kp.encrypted_private_key) {
                let decrypted = decrypt_symmetric(master_key, &encrypted_bytes);
                kp.decrypted_private_key = Some(b64_encode(&decrypted));
            }
        }
    }
}

pub fn encrypt_symmetric(master: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let key = aead::SecretKey::from_slice(master).expect("Invalid key size");
    aead::seal(&key, plaintext).expect("encryption failed")
}

pub fn decrypt_symmetric(master: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let key = aead::SecretKey::from_slice(master).expect("Invalid key size");
    aead::open(&key, ciphertext).expect("decryption failed")
}

pub fn sign_message(private_key_b64: &str, message: &[u8]) -> Vec<u8> {
    let private_key = b64_decode(private_key_b64).expect("invalid base64 for private key");
    let sk = dilithium3::SecretKey::from_bytes(&private_key).unwrap();
    dilithium3::detached_sign(message, &sk).as_bytes().to_vec()
}

pub fn verify_signature(public_key_b64: &str, message: &[u8], signature: &[u8]) -> bool {
    let public_key = b64_decode(public_key_b64).expect("invalid base64 for public key");
    let pk = dilithium3::PublicKey::from_bytes(&public_key).unwrap();
    let sig = dilithium3::DetachedSignature::from_bytes(signature).unwrap();
    dilithium3::verify_detached_signature(&sig, message, &pk).is_ok()
}

pub async fn send_matrix_message(message: &str) -> Result<(), matrix_sdk::Error> {
    let homeserver = "https://matrix.org";
    let client = Client::builder()
        .homeserver_url(homeserver)
        .build()
        .await
        .unwrap();

    client.matrix_auth().login_username("@your_bot:matrix.org", "your_password")
        .await
        .unwrap();

    let admin_user = user_id!("@admin:matrix.org");
    if let Some(room) = client.get_dm_room(admin_user) {
        room.send(RoomMessageEventContent::text_plain(message));
        return Ok(());
    }

    // No DM yet? Create one
    let mut request = CreateRoomRequest::new();

    request.invite = vec![admin_user.clone().into()];
    request.is_direct = true;
    request.preset = Some(RoomPreset::TrustedPrivateChat);

    let room: Room = client.create_room(request).await?;

    room.send(RoomMessageEventContent::text_plain(message)).await?;

    Ok(())
}

async fn verify_master_key(key: &[u8]) -> bool {
    let encrypted_validation = b64_decode(ENCRYPTED_VALIDATION).expect("invalid base64 in validation");
    let decrypted = decrypt_symmetric(key, &encrypted_validation);
    decrypted == VALIDATION_PLAINTEXT.as_bytes()
}
