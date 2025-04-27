mod proof_record;
mod hashalgorithm;
mod database;
mod dilithium;
mod api;
mod statistics;

use crate::database::Database;
use crate::api::{app, AppState};

use axum::serve;
use tokio::net::TcpListener;
use std::net::SocketAddr;
use std::sync::Arc;
use crate::statistics::Statistics;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Bind address hardcoded (or you can make it a const if you want)
    let addr = "0.0.0.0:3000".to_string();
    let socket_addr: SocketAddr = addr.parse()?;

    println!("🔌 Connecting to Cassandra...");
    let cassandra_session = Database::connect().await;
    let db = Arc::new(Database::new(cassandra_session));

    println!("✅ Connected to Cassandra!");

    println!("🔌 Initializing statistics database...");
    let stats = Arc::new( Statistics::new("statistics.db"));
    stats.clone().start_auto_flush();
    println!("✅ Statistics database ready!");

    let state = Arc::new(AppState { db, stats });
    let app = app(state);

    println!("🚀 Server running at http://{}/", socket_addr);

    // Bind manually with TcpListener
    let listener = TcpListener::bind(socket_addr).await?;
    serve(listener, app).await?;

    Ok(())
}
