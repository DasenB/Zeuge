use chrono::{DateTime, Utc};
use regex::Regex;

use crate::hashalgorithm::{hash, HashAlgorithm};
use crate::hashbundle::HashValue;

#[derive(Debug)]
pub struct HashRecord {
    pub hash: String,
    pub algorithm: HashAlgorithm,
    pub timestamp: DateTime<Utc>,
    pub comment: Option<String>,
}


impl HashRecord {
    pub fn new(hash_value: &HashValue, comment:  Option<String>, timestamp: DateTime<Utc>) -> Result<Self, String> {

        let max_comment_length = 200;

        if let Some(ref c) = comment {
            if c.len() > max_comment_length {
                return Err(format!(
                    "Comment is too long ({} characters). Max allowed is {}.",
                    c.len(),
                    max_comment_length
                ));
            }
        }


        let record =  HashRecord{
            hash: hash_value.hash.clone(),
            algorithm: hash_value.algorithm,
            timestamp,
            comment,
        };

        let hex_re = Regex::new(r"^[0-9a-fA-F]+$").unwrap();

        let expected_length = match record.algorithm {
            HashAlgorithm::SHA2_256 => 64,
            HashAlgorithm::SHA2_512 => 128,
            HashAlgorithm::SHA3_256 => 64,
            HashAlgorithm::SHA3_512 => 128,
        };

        if record.hash.len() != expected_length {
            return Err(format!(
                "{:?} must have a length of {}, found {}",
                record.algorithm,
                expected_length,
                record.hash.len()
            ));
        }
        if !hex_re.is_match(record.hash.as_str()) {
            return Err(format!("{:?} contains invalid characters", record.algorithm));
        }

        Ok(record)
    }

    pub fn verify(&self, input: &str) -> Result<(), String> {
        let actual = hash(self.algorithm, input);
        if self.hash.to_lowercase() == actual.to_lowercase() {
            Ok(())
        } else {
            Err(format!(
                "Hash mismatch for {:?}: expected {}, got {}",
                self.algorithm, self.hash, actual
            ))
        }
    }

}

