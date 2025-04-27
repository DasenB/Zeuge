use serde::Deserialize;
use regex::Regex;

#[derive(Debug, Deserialize)]
pub struct HashSet {
    pub hash_sha3_512: String,
    pub hash_sha3_256: String,
    pub hash_sha2_512: String,
    pub hash_sha2_256: String,
}

impl HashSet {
    pub fn from_json(json_str: &str) -> Result<Self, String> {
        let parsed: HashSet = serde_json::from_str(json_str)
            .map_err(|e| format!("JSON parse error: {}", e))?;

        let hex_re = Regex::new(r"^[0-9a-fA-F]+$").unwrap();

        let checks = [
            ("hash_sha3_512", 128, &parsed.hash_sha3_512),
            ("hash_sha3_256", 64, &parsed.hash_sha3_256),
            ("hash_sha2_512", 128, &parsed.hash_sha2_512),
            ("hash_sha2_256", 64, &parsed.hash_sha2_256),
        ];

        for (name, expected_len, value) in checks {
            if value.len() != expected_len {
                return Err(format!(
                    "{} must have a length of {}, found {}",
                    name,
                    expected_len,
                    value.len()
                ));
            }
            if !hex_re.is_match(value) {
                return Err(format!("{} contains invalid characters", name));
            }
        }

        Ok(parsed)
    }

    pub fn verify(&self, input: &str) -> Result<(), String> {

        let hash_sha3_512 = hash_sha3_512(input);
        let hash_sha3_256 = hash_sha3_256(input);
        let hash_sha2_512 = hash_sha2_512(input);
        let hash_sha2_256 = hash_sha2_256(input);

        let checks = [
            ("SHA3-512", &self.hash_sha3_512, &hash_sha3_512),
            ("SHA3-256", &self.hash_sha3_256, &hash_sha3_256),
            ("SHA2-512", &self.hash_sha2_512, &hash_sha2_512),
            ("SHA2-256", &self.hash_sha2_256, &hash_sha2_256),
        ];

        for (name, expected, actual) in checks {
            if expected.to_lowercase() != actual.to_lowercase() {
                return Err(format!("{} mismatch: expected {}, got {}", name, expected, actual));
            }
        }

        Ok(())
    }
}
