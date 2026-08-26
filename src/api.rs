use crate::config::Config;
use crate::error::{Error, Result};
use crate::queue::Spool;
use axum::extract::State;
use axum::http::{header::AUTHORIZATION, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;

#[derive(Debug, Deserialize)]
pub struct SendRequest {
    pub from: String,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub html: String,
}

#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub spool: Arc<Spool>,
}

/// Build the axum router. Exposed separately so integration tests can drive
/// it in-process.
pub fn router(config: Arc<Config>, spool: Arc<Spool>) -> Router {
    let state = AppState { config, spool };
    let auth_state = state.clone();

    Router::new()
        .route("/health", get(health))
        .route(
            "/send",
            post(send_email).layer(middleware::from_fn_with_state(auth_state, auth)),
        )
        .with_state(state)
}

/// Run the REST API server until the shutdown signal fires.
pub async fn run(
    config: Arc<Config>,
    spool: Arc<Spool>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(&config.api.listen)
        .await
        .map_err(|e| Error::Config(format!("cannot bind api.listen {}: {e}", config.api.listen)))?;
    tracing::info!(listen = %config.api.listen, "REST API listening");

    axum::serve(listener, router(config, spool))
        .with_graceful_shutdown(shutdown_signal(shutdown))
        .await
        .map_err(Error::Io)
}

async fn shutdown_signal(mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

async fn auth(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let bearer = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string);

    let authorized = match bearer {
        Some(bearer) => {
            let tokens = state.config.api.tokens.clone();
            // Argon2 verification is CPU/memory-heavy; keep it off the
            // async worker threads. Deny on join failure (safe default).
            tokio::task::spawn_blocking(move || {
                tokens.iter().any(|expected| expected.token.verify(&bearer))
            })
            .await
            .unwrap_or(false)
        }
        None => false,
    };

    if authorized {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                error: "unauthorized".into(),
            }),
        )
            .into_response()
    }
}

async fn send_email(State(state): State<AppState>, Json(req): Json<SendRequest>) -> Response {
    match build_and_enqueue(&state, &req).await {
        Ok(id) => (
            StatusCode::ACCEPTED,
            Json(json!({ "id": id, "status": "queued" })),
        )
            .into_response(),
        Err(e) => {
            // 4xx can echo the validation error; 5xx must not leak internal
            // details (paths, spool/IO errors) to the client.
            let (status, msg) = match &e {
                Error::InvalidInput(_) => (StatusCode::BAD_REQUEST, e.to_string()),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                ),
            };
            tracing::error!("REST send failed: {e}");
            (status, Json(ApiError { error: msg })).into_response()
        }
    }
}

async fn build_and_enqueue(state: &AppState, req: &SendRequest) -> Result<String> {
    let mut recipients = Vec::new();
    for addr in req.to.iter().chain(req.cc.iter()).chain(req.bcc.iter()) {
        if !crate::message::is_valid_email(addr) {
            return Err(Error::InvalidInput(format!(
                "invalid recipient address {addr:?}"
            )));
        }
        recipients.push(addr.trim().to_lowercase());
    }
    if recipients.is_empty() {
        return Err(Error::InvalidInput(
            "at least one of to/cc/bcc is required".into(),
        ));
    }
    if recipients.len() > state.config.max_recipients {
        return Err(Error::InvalidInput(format!(
            "too many recipients ({}); maximum is {}",
            recipients.len(),
            state.config.max_recipients
        )));
    }
    if !crate::message::is_valid_email(&req.from) {
        return Err(Error::InvalidInput(format!(
            "invalid from address {:?}",
            req.from
        )));
    }

    let outgoing = crate::message::Outgoing {
        from: req.from.clone(),
        to: req.to.clone(),
        cc: req.cc.clone(),
        bcc: req.bcc.clone(),
        subject: Some(req.subject.clone()),
        text: if req.text.is_empty() {
            None
        } else {
            Some(req.text.clone())
        },
        html: if req.html.is_empty() {
            None
        } else {
            Some(req.html.clone())
        },
    };
    let body = crate::message::build(&outgoing)?;
    let from = req.from.trim().to_lowercase();

    state.spool.enqueue(from, recipients, body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApiToken;
    use crate::secret::Secret;
    use argon2::password_hash::{PasswordHasher, SaltString};
    use argon2::{Algorithm, Argon2, Params, Version};
    use axum::body::Body;
    use tower::ServiceExt;

    #[tokio::test]
    async fn rejects_invalid_recipients() {
        let config = Arc::new(Config::default());
        let (spool, _rx) = Spool::open(std::env::temp_dir().join("mm-test-api")).unwrap();
        let state = AppState { config, spool };
        let req = SendRequest {
            from: "a@b.com".into(),
            to: vec!["not-an-email".into()],
            cc: vec![],
            bcc: vec![],
            subject: String::new(),
            text: String::new(),
            html: String::new(),
        };
        assert!(build_and_enqueue(&state, &req).await.is_err());
    }

    #[tokio::test]
    async fn rejects_empty_recipients() {
        let config = Arc::new(Config::default());
        let (spool, _rx) = Spool::open(std::env::temp_dir().join("mm-test-api2")).unwrap();
        let state = AppState { config, spool };
        let req = SendRequest {
            from: "a@b.com".into(),
            to: vec![],
            cc: vec![],
            bcc: vec![],
            subject: String::new(),
            text: String::new(),
            html: String::new(),
        };
        assert!(build_and_enqueue(&state, &req).await.is_err());
    }

    #[tokio::test]
    async fn enqueues_valid_message() {
        let config = Arc::new(Config::default());
        let (spool, _rx) = Spool::open(std::env::temp_dir().join("mm-test-api3")).unwrap();
        let state = AppState { config, spool };
        let req = SendRequest {
            from: "a@b.com".into(),
            to: vec!["c@d.com".into()],
            cc: vec![],
            bcc: vec![],
            subject: "Hi".into(),
            text: "hello".into(),
            html: String::new(),
        };
        let id = build_and_enqueue(&state, &req).await.unwrap();
        assert!(!id.is_empty());
    }

    /// Hash with deliberately weak parameters so tests stay fast.
    fn fast_phc_hash(password: &str) -> String {
        let salt =
            SaltString::from_b64("c3RhdGljIHNhbHQgMTIzNDU2").expect("valid static test salt");
        let params = Params::new(1024, 1, 1, Some(32)).expect("valid static test params");
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        argon
            .hash_password(password.as_bytes(), &salt)
            .expect("test password hashes")
            .to_string()
    }

    fn authed_router(tokens: Vec<ApiToken>) -> Router {
        let mut config = Config::default();
        config.api.tokens = tokens;
        let (spool, _rx) = Spool::open(std::env::temp_dir().join("mm-test-api-auth")).unwrap();
        router(Arc::new(config), spool)
    }

    async fn post_send(app: Router, bearer: Option<&str>) -> StatusCode {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/send")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"from":"a@b.com","to":["c@d.com"],"text":"hi"}"#,
            ))
            .unwrap();
        if let Some(bearer) = bearer {
            request
                .headers_mut()
                .insert(AUTHORIZATION, format!("Bearer {bearer}").parse().unwrap());
        }
        let response = app.oneshot(request).await.unwrap();
        response.status()
    }

    #[tokio::test]
    async fn rejects_missing_bearer() {
        let app = authed_router(vec![ApiToken {
            name: "ci".into(),
            token: Secret::Literal("tok-1".into()),
        }]);
        assert_eq!(post_send(app, None).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_wrong_bearer() {
        let app = authed_router(vec![ApiToken {
            name: "ci".into(),
            token: Secret::Literal("tok-1".into()),
        }]);
        assert_eq!(
            post_send(app.clone(), Some("nope")).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post_send(app, Some("TOK-1")).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn accepts_literal_token() {
        let app = authed_router(vec![
            ApiToken {
                name: "ci".into(),
                token: Secret::Literal("tok-1".into()),
            },
            ApiToken {
                name: "deploy".into(),
                token: Secret::Literal("tok-2".into()),
            },
        ]);
        assert_eq!(
            post_send(app.clone(), Some("tok-2")).await,
            StatusCode::ACCEPTED
        );
        assert_eq!(post_send(app, Some("nope")).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn accepts_argon2_token() {
        let app = authed_router(vec![ApiToken {
            name: "ci".into(),
            token: Secret::Argon2(fast_phc_hash("tok-argon")),
        }]);
        assert_eq!(
            post_send(app.clone(), Some("tok-argon")).await,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            post_send(app, Some("wrong")).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn health_needs_no_auth() {
        let app = authed_router(vec![ApiToken {
            name: "ci".into(),
            token: Secret::Literal("tok-1".into()),
        }]);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
