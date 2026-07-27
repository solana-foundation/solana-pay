use axum::{
    extract::{Json, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use pay_core::client::x402::{Challenge, ChallengeRequirements};
use pay_core::accounts::{AccountsFile, FileAccountsStore};
use pay_core::keystore::Keystore;
use pay_core::x402;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct AppState {
    accounts_store: Arc<FileAccountsStore>,
    keystore: Keystore,
}

#[derive(Deserialize)]
struct ScanRequest {
    repo: String,
}

#[derive(Serialize)]
struct Vulnerability {
    id: String,
    severity: String,
    description: String,
}

#[derive(Serialize)]
struct ScanReport {
    repo: String,
    vulnerabilities: Vec<Vulnerability>,
}

#[tokio::main]
async fn main() {
    // Load accounts store and keystore
    let accounts_store = Arc::new(FileAccountsStore::default_path());
    let keystore = Keystore::file(std::path::PathBuf::from("bug-bounty-intel.key"));

    let state = AppState {
        accounts_store,
        keystore,
    };

    let app = Router::new()
        .route("/api/bug-intel", get(get_challenge).post(post_scan))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("Bug Bounty Intelligence MCP server listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn get_challenge(State(state): State<AppState>) -> impl IntoResponse {
    // Build an x402 challenge with dummy requirements
    let challenge = Challenge {
        requirements: ChallengeRequirements {
            amount: "1000000".to_string(), // 1 USDC in base units (6 decimals)
            currency: "USDC".to_string(),
            recipient: "So11111111111111111111111111111111111111112".to_string(),
            description: Some("Bug Bounty Intelligence scan payment".to_string()),
            cluster: Some("mainnet".to_string()),
            recent_blockhash: None,
        },
        ephemeral_notice: None,
        headers: vec![],
    };

    let challenge_header = x402::format_www_authenticate(&challenge).unwrap_or_default();

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_str(&challenge_header).unwrap(),
    );

    (StatusCode::PAYMENT_REQUIRED, headers, "Payment required to run scan")
}

async fn post_scan(
    State(state): State<AppState>,
    Json(payload): Json<ScanRequest>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Verify payment proof from headers
    let payment_header = headers
        .get(x402::X402_V2_PAYMENT_HEADER)
        .or_else(|| headers.get(x402::X402_V1_PAYMENT_HEADER));

    if payment_header.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            "Missing payment proof header".to_string(),
        );
    }

    // Here you would verify the payment proof using pay_core and the keystore.
    // For demonstration, we accept any payment proof.

    // Return a dummy ranked vulnerability report
    let report = ScanReport {
        repo: payload.repo,
        vulnerabilities: vec![
            Vulnerability {
                id: "CVE-2023-0001".to_string(),
                severity: "High".to_string(),
                description: "Reentrancy vulnerability in contract XYZ".to_string(),
            },
            Vulnerability {
                id: "CVE-2023-0002".to_string(),
                severity: "Medium".to_string(),
                description: "Unchecked call return value in contract ABC".to_string(),
            },
        ],
    };

    (StatusCode::OK, axum::Json(report))
}
