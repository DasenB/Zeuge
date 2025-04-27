use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

pub fn hash(algorithm: HashAlgorithm, input: &str) -> String {
    match algorithm {
        HashAlgorithm::SHA2_256 => compute_hash::<Sha256>(input),
        HashAlgorithm::SHA2_512 => compute_hash::<Sha512>(input),
        HashAlgorithm::SHA3_256 => compute_hash::<Sha3_256>(input),
        HashAlgorithm::SHA3_512 => compute_hash::<Sha3_512>(input),
    }
}

fn compute_hash<D: Digest>(input: &str) -> String {
    let mut hasher = D::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Copy, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum HashAlgorithm {
    SHA2_256,
    SHA2_512,
    SHA3_256,
    SHA3_512,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HashValue {
    pub hash: String,
    pub algorithm: HashAlgorithm,
}

impl HashValue {
    /// Constructor: create a HashValue from cleartext input
    pub fn from_plaintext(algorithm: HashAlgorithm, input: &str) -> Self {
        let hash = hash(algorithm, input);
        Self { hash, algorithm }
    }

    /// Constructor: create a HashValue from a precomputed hash string
    pub fn from_hash(algorithm: HashAlgorithm, hash: String) -> Result<Self, String> {
        // Hash format validation
        let expected_length = match algorithm {
            HashAlgorithm::SHA2_256 => 64,
            HashAlgorithm::SHA2_512 => 128,
            HashAlgorithm::SHA3_256 => 64,
            HashAlgorithm::SHA3_512 => 128,
        };

        let hex_re = Regex::new(r"^[0-9a-fA-F]+$").unwrap();

        if hash.len() != expected_length {
            return Err(format!(
                "Hash length mismatch for algorithm {:?}: expected {} but got {} characters",
                algorithm,
                expected_length,
                hash.len()
            ));
        }

        if !hex_re.is_match(&hash) {
            return Err(format!("Hash contains invalid characters (not hex)"));
        }

        Ok(Self { algorithm, hash })
    }

    /// Verify if the provided input matches the stored hash
    pub fn verify(&self, input: &str) -> bool {
        let computed = hash(self.algorithm, input);
        self.hash.eq_ignore_ascii_case(&computed)
    }
}
