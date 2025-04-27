use chrono::{Utc};
use serde::{Deserialize, Serialize};
use crate::hashalgorithm::HashAlgorithm;
use crate::hashrecord::HashRecord;

#[derive(Debug, Deserialize, Serialize)]
pub struct HashBundle {
    pub hashes: Vec<HashValue>,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HashValue {
    pub hash: String,
    pub algorithm: HashAlgorithm,
}


impl HashBundle {

    pub fn to_records(&self) -> Vec<Result<HashRecord, String>> {
        let now = Utc::now();
        self.hashes
            .iter()
            .map(|hv| {
                HashRecord::new(hv, self.comment.clone(), now)
            })
            .collect()
    }

    pub fn from_json(json_str: &str) -> Result<Self, String> {
        let parsed: HashBundle = serde_json::from_str(json_str)
            .map_err(|e| format!("JSON parse error: {}", e))?;
        Ok(parsed)
    }

}