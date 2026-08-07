//! OpenID Connect discovery document and JWKS publication.

use axum::{Json, extract::State, http::header, response::IntoResponse};
use serde_json::{Value, json};

use crate::app_state::AppState;

pub(super) async fn discovery(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "issuer": state.issuer,
        "jwks_uri": format!("{}/.well-known/jwks.json", state.issuer),
        "token_endpoint": format!("{}/v1/token", state.issuer),
        "id_token_signing_alg_values_supported": ["ES256"],
        "subject_types_supported": ["public"]
    }))
}

pub(super) async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(
            header::CACHE_CONTROL,
            "public, max-age=300, must-revalidate",
        )],
        Json(state.jwt.jwks()),
    )
}
