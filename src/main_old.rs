mod proof_record;
mod hashalgorithm;
mod database;
mod dilithium;

use crate::hashalgorithm::{HashAlgorithm, HashValue};
use crate::proof_record::ProofRecord;
use crate::database::Database;
use crate::dilithium::*;

use chrono::{Utc, Duration};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to the Cassandra database
    let cassandra_session = Database::connect().await;
    let db = Database::new(cassandra_session);

    println!("✅ Connected to Cassandra successfully!");

    // Example input
    let value_str = "test input string";

    // Choose an algorithm
    let algorithm = HashAlgorithm::SHA2_256;

    // 🔥 Generate a Dilithium quantum-safe keypair
    let keypair = generate_dilithium_keypair();

    // 🔥 Create the hash value
    let hash_value = HashValue::from_plaintext(algorithm, value_str);

    // 🔥 Create the ProofRecord without a signature first
    let now = Utc::now();
    let mut proof = ProofRecord::new(
        hash_value,
        keypair.public_key.clone(), // Base64 public key
        String::new(),               // Temporary empty signature
        "Test comment".to_string(),  // Example comment
        now,
    )?;

    // 🔥 Sign the ProofRecord properly
    let signature = proof.sign(&keypair.secret_key)?;
    proof.signature = signature;

    println!(
        "✅ Created and signed ProofRecord with algorithm {:?}, hash {}, timestamp {}",
        proof.hash_value.algorithm,
        proof.hash_value.hash,
        proof.timestamp
    );

    // 🔥 Store the ProofRecord into the database
    db.store_hash(&proof).await;
    println!("✅ Stored ProofRecord in database");

    // Wait a tiny moment to ensure write is flushed (sometimes needed)
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // 🧪 1. Load by hash
    if let Some(loaded) = db.get_by_hash(&proof.hash_value.hash).await {
        println!("✅ Retrieved by hash: {:?}", loaded);

        assert_eq!(loaded.hash_value.hash, proof.hash_value.hash);
        assert_eq!(loaded.public_key, proof.public_key);
        assert_eq!(loaded.comment, proof.comment);

        // ✅ Verify the signature!
        match loaded.verify_signature() {
            Ok(_) => println!("✅ Signature verified successfully!"),
            Err(e) => println!("❌ Signature verification failed: {}", e),
        }
    } else {
        println!("❌ Could not load proof by hash");
    }

    // 🧪 2. Load by public key
    let loaded_by_pubkey = db.get_by_publickey(&proof.public_key, 0, 10).await;
    if !loaded_by_pubkey.is_empty() {
        println!("✅ Retrieved {} record(s) by public key", loaded_by_pubkey.len());

        let first = &loaded_by_pubkey[0];
        assert_eq!(first.hash_value.hash, proof.hash_value.hash);

        // ✅ Verify the signature!
        match first.verify_signature() {
            Ok(_) => println!("✅ Signature verified successfully!"),
            Err(e) => println!("❌ Signature verification failed: {}", e),
        }
    } else {
        println!("❌ Could not load proof by public key");
    }

    // 🧪 3. Load by block + timerange
    let block = now.format("%Y-%m-%d-%H-%M").to_string();
    let loaded_by_block = db.get_by_block_and_timerange(
        &block,
        now - Duration::minutes(1),
        now + Duration::minutes(1),
    ).await;

    if !loaded_by_block.is_empty() {
        println!("✅ Retrieved {} record(s) by block + time", loaded_by_block.len());

        let first = &loaded_by_block[0];
        assert_eq!(first.hash_value.hash, proof.hash_value.hash);

        // ✅ Verify the signature!
        match first.verify_signature() {
            Ok(_) => println!("✅ Signature verified successfully!"),
            Err(e) => println!("❌ Signature verification failed: {}", e),
        }
    } else {
        println!("❌ Could not load proof by block/time");
    }

    println!("🎉 All tests done!");

    Ok(())
}
