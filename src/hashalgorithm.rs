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

#[derive(Debug, Deserialize, Serialize)]
pub struct HashValue {
    pub hash: String,
    pub algorithm: HashAlgorithm,
}

