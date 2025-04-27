
mod hashrecord;
mod hashbundle;
mod hashalgorithm;
mod cassandra;
mod keymanager;
mod database;
mod proof_record;

use serde_json;

use crate::hashalgorithm::{hash, HashAlgorithm};
use crate::hashbundle::{HashBundle, HashValue};
use crate::hashrecord::HashRecord;
use crate::cassandra::CassandraDb;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>  {

    let c = CassandraDb::connect("127.0.0.1").await?;
    println!("Connected successfully!");

    let value_str = "test";

    let algorithms = vec![
        HashAlgorithm::SHA2_256,
        HashAlgorithm::SHA2_512,
        HashAlgorithm::SHA3_256,
        HashAlgorithm::SHA3_512,
    ];

    let bundle = HashBundle {
        comment: Some("test test".into()),
        hashes: algorithms.iter().map(|a| {
            HashValue {
                hash: hash(*a, value_str.clone()),
                algorithm: *a
            }
        }).collect()
    };

    let json_str = serde_json::to_string_pretty(&bundle).unwrap();

    match HashBundle::from_json(&json_str) {
        Ok(bundle) => {
            match &bundle.comment {
                Some(comment) => println!("✅ Detected Bundle with comment: {}", comment),
                None => println!("✅ Detected Bundle with no comment"),
            }
            for result in bundle.to_records() {
                match result {
                    Ok(record) => println!("✅ Created record with algorithm {:?} and hash {} and time {}", record.algorithm, record.hash, record.timestamp),
                    Err(e) => println!("❌ Failed to create record: {}", e),
                }
            }
        }
        Err(e) => println!("❌ JSON parse error: {}", e),
    }

    Ok(())


}