use cdrs_tokio::authenticators::NoneAuthenticator;
use cdrs_tokio::cluster::{session::Session, session::new as connect_cassandra, TcpConnectionPool, NodeTcpConfigBuilder, ClusterTcpConfig};
use cdrs_tokio::query::*;
use cdrs_tokio::frame::TryFromRow;
use cdrs_tokio::load_balancing::RoundRobin;
use cdrs_tokio::types::prelude::*;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use cdrs_tokio::query_values;
use std::result::Result as StdResult;
use cdrs_tokio::types::IntoRustByName;
use crate::hashalgorithm::{HashAlgorithm, HashValue};
use crate::proof_record::ProofRecord;

type CassandraSession = Session<RoundRobin<TcpConnectionPool>>;

impl TryFromRow for ProofRecord {
    fn try_from_row(row: Row) -> StdResult<Self, cdrs_tokio::error::Error> {
        let hash: String = row.get_r_by_name("hash")?;
        let algorithm_str: String = row.get_r_by_name("algorithm")?;
        let algorithm = match algorithm_str.as_str() {
            "SHA2_256" => HashAlgorithm::SHA2_256,
            "SHA2_512" => HashAlgorithm::SHA2_512,
            "SHA3_256" => HashAlgorithm::SHA3_256,
            "SHA3_512" => HashAlgorithm::SHA3_512,
            other => {
                return Err(cdrs_tokio::error::Error::from(
                    format!("Unknown hash algorithm: {}", other)
                ));
            }
        };

        let hash_value = HashValue::from_hash(algorithm, hash)
            .map_err(cdrs_tokio::error::Error::from)?;

        // 👇 No generics here! Just normal call.
        let public_key: Option<String> = match row.get_r_by_name("public_key") {
            Ok(v) => Some(v),
            Err(_) => None,
        };

        let comment: Option<String> = match row.get_r_by_name("comment") {
            Ok(v) => Some(v),
            Err(_) => None,
        };

        let signature: Option<String> = match row.get_r_by_name("signature") {
            Ok(v) => Some(v),
            Err(_) => None,
        };

        Ok(Self {
            hash_value,
            public_key,
            timestamp: row.get_r_by_name("timestamp")?,
            comment,
            signature,
        })
    }
}



pub struct Database {
    session: Arc<CassandraSession>,
}

impl Database {
    pub async fn connect() -> CassandraSession {
        let auth = Arc::new(NoneAuthenticator);
        let node = NodeTcpConfigBuilder::new("127.0.0.1:9042", auth).build();
        let lb = RoundRobin::new();
        let nodes = ClusterTcpConfig(vec![node]);

        connect_cassandra(&nodes, lb)
            .await
            .expect("Failed to connect to Cassandra")
    }

    pub fn new(session: CassandraSession) -> Self {
        Self {
            session: Arc::new(session),
        }
    }

    pub async fn store_hash(&self, record: &ProofRecord) -> Result<()> {
        let block = record.timestamp.format("%Y-%m-%d-%H-%M").to_string();

        // --- Insert into proofs_by_hash ---
        let mut fields_hash = vec!["hash", "timestamp", "algorithm"];
        let mut placeholders_hash = vec!["?", "?", "?"];
        let mut values_hash: Vec<Value> = vec![
            Value::new_normal(record.hash_value.hash.clone()),
            Value::new_normal(record.timestamp),
            Value::new_normal(format!("{:?}", record.hash_value.algorithm)),
        ];

        if let Some(public_key) = &record.public_key {
            fields_hash.push("public_key");
            placeholders_hash.push("?");
            values_hash.push(Value::new_normal(public_key.clone()));
        }
        if let Some(comment) = &record.comment {
            fields_hash.push("comment");
            placeholders_hash.push("?");
            values_hash.push(Value::new_normal(comment.clone()));
        }
        if let Some(signature) = &record.signature {
            fields_hash.push("signature");
            placeholders_hash.push("?");
            values_hash.push(Value::new_normal(signature.clone()));
        }

        let insert_hash = format!(
            "INSERT INTO zeuge.proofs_by_hash ({}) VALUES ({})",
            fields_hash.join(", "),
            placeholders_hash.join(", ")
        );

        self.session
            .query_with_values(insert_hash, QueryValues::SimpleValues(values_hash))
            .await
            .map_err(|e| format!("Insert into proofs_by_hash error: {:?}", e))?;

        // --- Insert into proofs_by_pubkey if public_key exists ---
        if let Some(public_key) = &record.public_key {
            let mut fields_pubkey = vec!["public_key", "timestamp", "hash", "algorithm"];
            let mut placeholders_pubkey = vec!["?", "?", "?", "?"];
            let mut values_pubkey: Vec<Value> = vec![
                Value::new_normal(public_key.clone()),
                Value::new_normal(record.timestamp),
                Value::new_normal(record.hash_value.hash.clone()),
                Value::new_normal(format!("{:?}", record.hash_value.algorithm)),
            ];

            if let Some(comment) = &record.comment {
                fields_pubkey.push("comment");
                placeholders_pubkey.push("?");
                values_pubkey.push(Value::new_normal(comment.clone()));
            }
            if let Some(signature) = &record.signature {
                fields_pubkey.push("signature");
                placeholders_pubkey.push("?");
                values_pubkey.push(Value::new_normal(signature.clone()));
            }

            let insert_pubkey = format!(
                "INSERT INTO zeuge.proofs_by_pubkey ({}) VALUES ({})",
                fields_pubkey.join(", "),
                placeholders_pubkey.join(", ")
            );

            self.session
                .query_with_values(insert_pubkey, QueryValues::SimpleValues(values_pubkey))
                .await
                .map_err(|e| format!("Insert into proofs_by_pubkey error: {:?}", e))?;
        }

        // --- Insert into proofs_by_block ---
        let mut fields_block = vec!["block", "timestamp", "hash", "algorithm"];
        let mut placeholders_block = vec!["?", "?", "?", "?"];
        let mut values_block: Vec<Value> = vec![
            Value::new_normal(block),
            Value::new_normal(record.timestamp),
            Value::new_normal(record.hash_value.hash.clone()),
            Value::new_normal(format!("{:?}", record.hash_value.algorithm)),
        ];

        if let Some(public_key) = &record.public_key {
            fields_block.push("public_key");
            placeholders_block.push("?");
            values_block.push(Value::new_normal(public_key.clone()));
        }
        if let Some(comment) = &record.comment {
            fields_block.push("comment");
            placeholders_block.push("?");
            values_block.push(Value::new_normal(comment.clone()));
        }
        if let Some(signature) = &record.signature {
            fields_block.push("signature");
            placeholders_block.push("?");
            values_block.push(Value::new_normal(signature.clone()));
        }

        let insert_block = format!(
            "INSERT INTO zeuge.proofs_by_block ({}) VALUES ({})",
            fields_block.join(", "),
            placeholders_block.join(", ")
        );

        self.session
            .query_with_values(insert_block, QueryValues::SimpleValues(values_block))
            .await
            .map_err(|e| format!("Insert into proofs_by_block error: {:?}", e))?;

        Ok(())
    }




    pub async fn get_by_hash(&self, hash: &str) -> Option<ProofRecord> {
        let rows = self.session.query_with_values(
            "SELECT hash, public_key, timestamp, comment, signature, algorithm FROM zeuge.proofs_by_hash WHERE hash = ?",
            query_values!(hash),
        ).await.unwrap().get_body().unwrap().into_rows();

        rows.and_then(|mut r| r.pop()).and_then(|row| ProofRecord::try_from_row(row).ok())
    }

    pub async fn get_by_publickey(&self, key: &str, page: usize, page_size: usize) -> Vec<ProofRecord> {
        let offset = page * page_size;
        let limit = offset + page_size; // <--- important: fetch enough rows

        let rows = self.session.query_with_values(
            format!(
                "SELECT hash, public_key, timestamp, comment, signature, algorithm FROM zeuge.proofs_by_pubkey WHERE public_key = ? LIMIT {}",
                limit
            ),
            query_values!(key),
        ).await.unwrap().get_body().unwrap().into_rows();

        rows.unwrap_or_default()
            .into_iter()
            .skip(offset)
            .filter_map(|row| ProofRecord::try_from_row(row).ok())
            .collect()
    }

    pub async fn get_by_block_and_timerange(&self, block: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<ProofRecord> {
        // LIMIT 5000 will not be okay anymore when the service grows and more than 5000 records are created
        let rows = self.session.query_with_values(
            "SELECT hash, public_key, timestamp, comment, signature, algorithm FROM zeuge.proofs_by_block WHERE block = ? AND timestamp >= ? AND timestamp <= ? LIMIT 5000",
            query_values!(block, start, end),
        ).await.unwrap().get_body().unwrap().into_rows();

        rows.unwrap_or_default()
            .into_iter()
            .filter_map(|row| ProofRecord::try_from_row(row).ok())
            .collect()
    }
}
