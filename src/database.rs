use cdrs_tokio::authenticators::NoneAuthenticator;
use cdrs_tokio::cluster::{session::Session, session::new as connect_cassandra, TcpConnectionPool, NodeTcpConfigBuilder, ClusterTcpConfig};
use cdrs_tokio::query::*;
use cdrs_tokio::frame::TryFromRow;
use cdrs_tokio::load_balancing::RoundRobin;
use cdrs_tokio::types::prelude::*;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use cdrs_tokio::query_values;
use cdrs_tokio::frame::frame_error::CDRSError;
use std::result::Result as StdResult;
use cdrs_tokio::types::IntoRustByName;

type CassandraSession = Session<RoundRobin<TcpConnectionPool>>;

use crate::proof_record::ProofRecord;

impl TryFromRow for ProofRecord {
    fn try_from_row(row: Row) -> StdResult<Self, cdrs_tokio::error::Error> {
        Ok(Self {
            hash: row.get_r_by_name("hash")?,
            public_key: row.get_r_by_name("public_key")?,
            timestamp: row.get_r_by_name("timestamp")?,
            comment: row.get_r_by_name("comment")?,
            signature: row.get_r_by_name("signature")?,
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

        let session = connect_cassandra(&nodes, lb)
            .await
            .expect("Failed to connect to Cassandra");

        session
    }

    pub async fn store_hash(&self, record: &ProofRecord) {
        let day = record.timestamp.format("%Y-%m-%d").to_string();

        let insert_main = "INSERT INTO proofs_by_hash (hash, public_key, timestamp, comment, signature) VALUES (?, ?, ?, ?, ?)";
        let insert_pubkey = "INSERT INTO proofs_by_pubkey (public_key, timestamp, hash, comment, signature) VALUES (?, ?, ?, ?, ?)";
        let insert_day = "INSERT INTO proofs_by_day (day, timestamp, hash, public_key, comment, signature) VALUES (?, ?, ?, ?, ?, ?)";

        let values = query_values!(record.hash.clone(), record.public_key.clone(), record.timestamp, record.comment.clone(), record.signature.clone());
        let values_pub = query_values!(record.public_key.clone(), record.timestamp, record.hash.clone(), record.comment.clone(), record.signature.clone());
        let values_day = query_values!(day, record.timestamp, record.hash.clone(), record.public_key.clone(), record.comment.clone(), record.signature.clone());

        self.session.query_with_values(insert_main, values).await.unwrap();
        self.session.query_with_values(insert_pubkey, values_pub).await.unwrap();
        self.session.query_with_values(insert_day, values_day).await.unwrap();
    }

    pub async fn get_by_hash(&self, hash: &str) -> Option<ProofRecord> {
        let rows = self.session.query_with_values(
            "SELECT hash, public_key, timestamp, comment, signature FROM proofs_by_hash WHERE hash = ?",
            query_values!(hash),
        ).await.unwrap().get_body().unwrap().into_rows();

        rows.and_then(|mut r| r.pop()).and_then(|row| ProofRecord::try_from_row(row).ok())
    }

    pub async fn get_by_publickey(&self, key: &str, page: usize, page_size: usize) -> Vec<ProofRecord> {
        let limit = page_size;
        let offset = page * page_size;

        let rows = self.session.query_with_values(
            format!("SELECT hash, public_key, timestamp, comment, signature FROM proofs_by_pubkey WHERE public_key = ? LIMIT {}", limit),
            query_values!(key),
        ).await.unwrap().get_body().unwrap().into_rows();

        rows.unwrap_or_default().into_iter().skip(offset).filter_map(|r|  ProofRecord::try_from_row(r).ok()).collect()
    }

    pub async fn get_by_timerange(&self, day: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<ProofRecord> {
        let rows = self.session.query_with_values(
            "SELECT hash, public_key, timestamp, comment, signature FROM proofs_by_day WHERE day = ? AND timestamp >= ? AND timestamp <= ?",
            query_values!(day, start, end),
        ).await.unwrap().get_body().unwrap().into_rows();

        rows.unwrap_or_default().into_iter().filter_map(|r|  ProofRecord::try_from_row(r).ok()).collect()
    }
}
