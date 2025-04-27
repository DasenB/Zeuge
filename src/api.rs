use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::database::Database;
use crate::proof_record::ProofRecord;
use crate::hashalgorithm::{HashAlgorithm, HashValue};
use crate::statistics::Statistics; // 🔥 New import!

pub struct AppState {
    pub db: Arc<Database>,
    pub stats: Arc<Statistics>, // 🔥 Added statistics to AppState
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/proofs/{hash}", get(get_proof_by_hash))
        .route("/proofs_by_pubkey", get(get_proofs_by_public_key))
        .route("/proofs_by_time", get(get_proofs_by_time))
        .route("/filter", post(filter_proofs))
        .route("/proofs", post(create_proof))
        .with_state(state)
}

#[derive(Deserialize)]
pub struct Pagination {
    pub page: Option<usize>,
    pub page_size: Option<usize>,
}

const MAX_PAGE_SIZE: usize = 1000;

async fn get_proof_by_hash(
    Path(hash): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match state.db.get_by_hash(&hash).await {
        Some(proof) => Ok(Json(proof)),
        None => Err((StatusCode::NOT_FOUND, Json("Proof not found"))),
    }
}

#[derive(Deserialize)]
pub struct PublicKeyQuery {
    pub public_key: Option<String>,
    pub page: Option<usize>,
    pub page_size: Option<usize>,
}

async fn get_proofs_by_public_key(
    Query(params): Query<PublicKeyQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let public_key = match params.public_key {
        Some(pk) => pk,
        None => return Err((StatusCode::BAD_REQUEST, "Missing public_key")),
    };

    let page = params.page.unwrap_or(0);
    let page_size = params.page_size.unwrap_or(10);

    if page_size > MAX_PAGE_SIZE {
        return Err((StatusCode::BAD_REQUEST, "page_size too large (max 1000)"));
    }

    let proofs = state.db.get_by_publickey(&public_key, page, page_size).await;

    Ok(Json(proofs))
}

#[derive(Deserialize)]
pub struct TimeQuery {
    pub start: Option<i64>,
    pub end: Option<i64>,
    pub page: Option<usize>,
    pub page_size: Option<usize>,
}

async fn get_proofs_by_time(
    Query(query): Query<TimeQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let start_ts = query.start.unwrap_or(0);
    let end_ts = query.end.unwrap_or(chrono::Utc::now().timestamp());

    let start_dt = chrono::DateTime::from_timestamp(start_ts, 0).unwrap_or_else(chrono::Utc::now);
    let end_dt = chrono::DateTime::from_timestamp(end_ts, 0).unwrap_or_else(chrono::Utc::now);

    let max_minutes = 60; // e.g., 1 hour
    let actual_minutes = (end_dt - start_dt).num_minutes();

    if actual_minutes > max_minutes {
        return Err((StatusCode::BAD_REQUEST, "Time range too big (max 1 hour)"));
    }

    let mut blocks = Vec::new();
    let mut cursor = start_dt;
    while cursor <= end_dt {
        blocks.push(cursor.format("%Y-%m-%d-%H-%M").to_string());
        cursor += chrono::Duration::minutes(1);
    }

    let mut all_proofs = Vec::new();
    for block in blocks {
        let mut proofs = state.db.get_by_block_and_timerange(&block, start_dt, end_dt).await;
        all_proofs.append(&mut proofs);
    }

    all_proofs.sort_by_key(|p| p.timestamp);

    let page = query.page.unwrap_or(0);
    let page_size = query.page_size.unwrap_or(10);

    if page_size > MAX_PAGE_SIZE {
        return Err((StatusCode::BAD_REQUEST, "page_size too large (max 1000)"));
    }

    let start_idx = page * page_size;
    let paginated_proofs = all_proofs.into_iter().skip(start_idx).take(page_size).collect::<Vec<_>>();

    Ok(Json(paginated_proofs))
}

#[derive(Deserialize)]
pub struct FilterQuery {
    pub hash: Option<String>,
    pub algorithm: Option<String>,
    pub comment: Option<String>,
    pub block: Option<String>,
    pub public_key: Option<String>,
}

async fn filter_proofs(
    State(state): State<Arc<AppState>>,
    Json(filter): Json<FilterQuery>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let mut results = Vec::new();

    if let Some(hash) = filter.hash {
        if let Some(proof) = state.db.get_by_hash(&hash).await {
            results.push(proof);
        }
    }

    if let Some(public_key) = filter.public_key {
        let proofs = state.db.get_by_publickey(&public_key, 0, 100).await;
        results.extend(proofs);
    }

    if let Some(block) = filter.block {
        let now = chrono::Utc::now();
        let proofs = state.db.get_by_block_and_timerange(&block, now - chrono::Duration::days(1), now).await;
        results.extend(proofs);
    }

    Ok(Json(results))
}

#[derive(Deserialize)]
pub struct CreateProofRequest {
    pub hash: String,
    pub algorithm: String,
    pub public_key: Option<String>,
    pub signature: Option<String>,
    pub comment: Option<String>,
}

async fn create_proof(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateProofRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if let Some(comment) = &payload.comment {
        if comment.len() > 200 {
            return Err((StatusCode::BAD_REQUEST, "Comment too long (max 200 chars)".to_string()));
        }
    }

    let algorithm = match payload.algorithm.as_str() {
        "SHA2_256" => HashAlgorithm::SHA2_256,
        "SHA2_512" => HashAlgorithm::SHA2_512,
        "SHA3_256" => HashAlgorithm::SHA3_256,
        "SHA3_512" => HashAlgorithm::SHA3_512,
        _ => return Err((StatusCode::BAD_REQUEST, "Unknown hash algorithm".to_string())),
    };

    let hash_value = HashValue::from_hash(algorithm, payload.hash.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let timestamp = chrono::Utc::now();

    let mut proof = ProofRecord::new(
        hash_value,
        payload.public_key.clone(),
        payload.signature.clone(),
        payload.comment.clone(),
        timestamp,
    ).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    if let (Some(public_key), Some(signature)) = (&payload.public_key, &payload.signature) {
        proof.public_key = Some(public_key.clone());
        proof.signature = Some(signature.clone());
        proof.verify_signature()
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Signature verification failed: {}", e)))?;
    } else if payload.public_key.is_some() || payload.signature.is_some() {
        return Err((StatusCode::BAD_REQUEST, "Both public_key and signature must be provided".to_string()));
    }

    state.stats.increment_block(timestamp);

    if let Err(e) = state.db.store_hash(&proof).await {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store proof: {}", e)));
    }

    Ok((StatusCode::CREATED, Json(proof)))
}
