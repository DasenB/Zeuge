use chrono::{DateTime, Utc};
use crate::hashalgorithm::HashValue;
use std::result::Result as StdResult;
use crate::dilithium::sign_message;
use serde::Serialize;

/// Domain model for a stored proof record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofRecord {
    pub hash_value: HashValue,
    pub public_key: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub comment: Option<String>,
    pub signature: Option<String>,
}

impl ProofRecord {
    /// Create a new ProofRecord with validation.
    pub fn new(
        hash_value: HashValue,
        public_key: Option<String>,
        signature: Option<String>,
        comment: Option<String>,
        timestamp: DateTime<Utc>,
    ) -> Result<Self, String> {
        let max_comment_length = 200;

        if let Some(ref comment_str) = comment {
            if comment_str.len() > max_comment_length {
                return Err(format!(
                    "Comment is too long ({} characters). Max allowed is {}.",
                    comment_str.len(),
                    max_comment_length
                ));
            }
        }

        // Validate public_key and signature
        match (&public_key, &signature) {
            (Some(pubkey), Some(sig)) => {
                // Try verifying
                let payload = serde_json::json!({
                    "hash": &hash_value.hash,
                    "hash_algorithm": format!("{:?}", hash_value.algorithm),
                    "comment": comment.clone().unwrap_or_default(),
                });

                let payload_json = serde_json::to_string(&payload)
                    .map_err(|_| "Failed to serialize ProofRecord for signature verification".to_string())?;

                crate::dilithium::verify_signature(pubkey, payload_json.as_bytes(), sig)
                    .map_err(|e| format!("Signature verification failed: {}", e))?;
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err("Both public_key and signature must be provided together".to_string());
            }
            (None, None) => { /* fine */ }
        }

        Ok(Self {
            hash_value,
            public_key,
            signature,
            comment,
            timestamp,
        })
    }


    /// Verifies that the provided input matches the stored hash.
    pub fn verify_hash(&self, input: &str) -> StdResult<(), String> {
        if self.hash_value.verify(input) {
            Ok(())
        } else {
            Err(format!(
                "Hash mismatch: expected {}, got {}",
                self.hash_value.hash,
                crate::hashalgorithm::hash(self.hash_value.algorithm, input),
            ))
        }
    }

    pub fn verify_signature(&self) -> StdResult<(), String> {
        use crate::dilithium::verify_signature;
        use serde::Serialize;

        #[derive(Serialize)]
        struct SignedPayload<'a> {
            hash: &'a str,
            hash_algorithm: &'a str,
            comment: &'a str,
        }

        let payload = SignedPayload {
            hash: &self.hash_value.hash,
            hash_algorithm: &format!("{:?}", self.hash_value.algorithm),
            comment: self.comment.as_deref().unwrap_or(""),
        };

        let payload_json = serde_json::to_string(&payload)
            .map_err(|_| "Failed to serialize payload for verification".to_string())?;

        verify_signature(
            self.public_key.as_deref().ok_or("Missing public key")?,
            payload_json.as_bytes(),
            self.signature.as_deref().ok_or("Missing signature")?,
        )
    }


    pub fn sign(&self, secret_key_b64: &str) -> StdResult<String, String> {
        #[derive(Serialize)]
        struct SignedPayload<'a> {
            hash: &'a str,
            hash_algorithm: &'a str,
            comment: &'a str,
        }

        let payload = SignedPayload {
            hash: &self.hash_value.hash,
            hash_algorithm: &format!("{:?}", self.hash_value.algorithm),
            comment: self.comment.as_deref().unwrap_or(""),
        };

        let payload_json = serde_json::to_string(&payload)
            .map_err(|_| "Failed to serialize ProofRecord payload".to_string())?;

        let signature = sign_message(secret_key_b64, payload_json.as_bytes());

        Ok(signature.signature)
    }
}


