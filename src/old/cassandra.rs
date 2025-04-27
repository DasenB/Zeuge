use cassandra_cpp::{Cluster, Session, Statement, Error, AsRustType};
use chrono::{DateTime, Utc};
use crate::{HashRecord, HashAlgorithm};

pub struct CassandraDb {
    session: Session,
}

impl CassandraDb {
    pub async fn connect(contact_points: &str) -> Result<Self, Error> {
        let mut cluster = Cluster::default();
        cluster.set_contact_points(contact_points)?;
        let session = cluster.connect().await?;
        Ok(Self { session })
    }

    pub async fn insert_hash_record(&self, record: &HashRecord) -> Result<(), Error> {
        let query = "INSERT INTO hash_records (hash, algorithm, timestamp, comment) VALUES (?, ?, ?, ?)";
        let prepared = self.session.prepare(query).await?;
        let mut stmt = prepared.bind();

        stmt.bind_string(0, &record.hash)?;
        stmt.bind_string(1, format!("{:?}", record.algorithm).as_str())?;
        stmt.bind_int64(2, record.timestamp.timestamp_millis())?;

        if let Some(comment) = &record.comment {
            stmt.bind_string(3, comment)?;
        } else {
            stmt.bind_null(3)?;
        }
        stmt.execute().await?;
        Ok(())
    }

    pub async fn get_hash_record(&self, hash: &str) -> Result<Option<HashRecord>, Error> {
        let query = "SELECT algorithm, timestamp, comment FROM hash_records WHERE hash = ?";
        let prepared = self.session.prepare(query).await?;
        let mut stmt = prepared.bind();
        stmt.bind_string(0, hash)?;

        let result = stmt.execute().await?;
        let row = result.first_row();

        if let Some(row) = row {
            let algorithm_str: String = row.get(0)?;
            let algorithm = match algorithm_str.as_str() {
                "SHA2_256" => HashAlgorithm::SHA2_256,
                "SHA2_512" => HashAlgorithm::SHA2_512,
                "SHA3_256" => HashAlgorithm::SHA3_256,
                "SHA3_512" => HashAlgorithm::SHA3_512,
                _ => return Err(Error::from("Invalid hash algorithm in database.")),
            };

            let timestamp_ms: i64 = row.get(1)?;
            let timestamp = DateTime::<Utc>::from_utc(
                chrono::NaiveDateTime::from_timestamp_millis(timestamp_ms).unwrap(),
                Utc,
            );

            let comment: Option<String> = match row.get(2) {
                Ok(c) => Some(c),
                Err(_) => None,
            };

            Ok(Some(HashRecord {
                hash: hash.to_string(),
                algorithm,
                timestamp,
                comment,
            }))
        } else {
            Ok(None)
        }
    }
}
