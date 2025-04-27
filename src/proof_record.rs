use chrono::{DateTime, Utc};
use regex::Regex;
use crate::hashalgorithm::{hash, HashAlgorithm}; // assuming you still have this
use crate::hashbundle::HashValue;
use cdrs_tokio::types::prelude::*;
use cdrs_tokio::frame::TryFromRow;
use std::result::Result as StdResult;

#[derive(Debug, Clone)]
pub struct ProofRecord {
    pub hash: String,
    pub public_key: String,
    pub timestamp: DateTime<Utc>,
    pub comment: String,
    pub signature: String,
}

impl ProofRecord {
    pub fn new(hash_value: &HashValue, public_key: String, signature: String, comment: String, timestamp: DateTime<Utc>) -> Result<Self, String> {
        let max_comment_length = 200;

        if comment.len() > max_comment_length {
            return Err(format!(
                "Comment is too long ({} characters). Max allowed is {}.",
                comment.len(),
                max_comment_length
            ));
        }

        let hex_re = Regex::new(r"^[0-9a-fA-F]+$").unwrap();

        let expected_length = match hash_value.algorithm {
            HashAlgorithm::SHA2_256 => 64,
            HashAlgorithm::SHA2_512 => 128,
            HashAlgorithm::SHA3_256 => 64,
            HashAlgorithm::SHA3_512 => 128,
        };

        if hash_value.hash.len() != expected_length {
            return Err(format!(
                "{:?} must have a length of {}, found {}",
                hash_value.algorithm,
                expected_length,
                hash_value.hash.len()
            ));
        }
        if !hex_re.is_match(hash_value.hash.as_str()) {
            return Err(format!("{:?} contains invalid characters", hash_value.algorithm));
        }

        Ok(Self {
            hash: hash_value.hash.clone(),
            public_key,
            timestamp,
            comment,
            signature,
        })
    }

    pub fn verify(&self, input: &str, algorithm: HashAlgorithm) -> Result<(), String> {
        let actual = hash(algorithm, input);
        if self.hash.to_lowercase() == actual.to_lowercase() {
            Ok(())
        } else {
            Err(format!(
                "Hash mismatch: expected {}, got {}",
                self.hash, actual
            ))
        }
    }
}
