use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use rusqlite::OptionalExtension;
use tokio::time::{interval, Duration};

#[derive(Clone)]
pub struct Statistics {
    db: Arc<Mutex<Connection>>,
    in_memory_counts: Arc<Mutex<HashMap<String, usize>>>,
}

impl Statistics {
    /// Initialize the statistics database
    pub fn new(db_path: &str) -> Self {
        let conn = Connection::open(db_path).expect("Failed to open statistics DB");

        conn.execute(
            "CREATE TABLE IF NOT EXISTS block_density (
                block TEXT PRIMARY KEY,
                count INTEGER NOT NULL
            )",
            [],
        )
            .expect("Failed to create block_density table");

        Self {
            db: Arc::new(Mutex::new(conn)),
            in_memory_counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Increase in-memory count for a block
    pub fn increment_block(&self, timestamp: DateTime<Utc>) {
        let block = timestamp.format("%Y-%m-%d-%H-%M").to_string();

        let mut counts = self
            .in_memory_counts
            .lock()
            .expect("Failed to lock in_memory_counts");

        *counts.entry(block).or_insert(0) += 1;
    }

    /// Flush finished blocks to the database
    pub fn flush_finished_blocks(&self) {
        let now_block = Utc::now().format("%Y-%m-%d-%H-%M").to_string();

        let mut counts = self
            .in_memory_counts
            .lock()
            .expect("Failed to lock in_memory_counts");

        let mut finished_blocks = Vec::new();

        for (block, count) in counts.iter() {
            if block < &now_block {
                finished_blocks.push((block.clone(), *count));
            }
        }

        if finished_blocks.is_empty() {
            return;
        }

        let mut conn = self.db.lock().expect("Failed to lock SQLite connection");

        let tx = conn.transaction().expect("Failed to start transaction");

        for (block, count) in finished_blocks.iter() {
            tx.execute(
                "INSERT INTO block_density (block, count)
                 VALUES (?1, ?2)
                 ON CONFLICT(block) DO UPDATE SET count = count + ?2",
                params![block, count],
            )
                .expect("Failed to insert or update block_density");
        }

        tx.commit().expect("Failed to commit transaction");

        // After successful flush, remove flushed blocks
        for (block, _) in finished_blocks {
            counts.remove(&block);
        }
    }

    /// Get density of a specific block
    pub fn get_block_density(&self, block: &str) -> usize {
        {
            // First check in-memory cache
            let counts = self.in_memory_counts.lock().unwrap();
            if let Some(count) = counts.get(block) {
                return *count;
            }
        }

        // If not in memory, query SQLite
        let conn = self.db.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT count FROM block_density WHERE block = ?1")
            .expect("Failed to prepare query");

        let result: Option<usize> = stmt
            .query_row(params![block], |row| row.get(0))
            .optional()
            .expect("Failed to query block_density");

        result.unwrap_or(0)
    }

    pub fn start_auto_flush(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60)); // Every 60 seconds
            loop {
                interval.tick().await;
                self.flush_finished_blocks();
            }
        });
    }
}
