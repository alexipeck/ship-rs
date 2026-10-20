use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct Email {
    pub email: String,
    pub primary: bool,
    pub verified: bool,
}

enum VerifiedClaim {
    Bool(bool),
    Text(String),
}

struct Pending {
    challenge: String,
    nonce: String,
    redirect: String,
    email: String,
    verified: VerifiedClaim,
}

struct GoogleInner {
    client_id: String,
    client_secret: String,
    email: Mutex<String>,
    verified: Mutex<bool>,
    verified_text: Mutex<Option<String>>,
    key: RsaPrivateKey,
    codes: Mutex<HashMap<String, Pending>>,
}

pub struct Google {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    inner: Arc<GoogleInner>,
    task: JoinHandle<()>,
}

impl Google {
    pub async fn start(client_id: &str, client_secret: &str, email: &str, verified: bool) -> Self {
        let mut rng = rand::rngs::OsRng;
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
        let inner = Arc::new(GoogleInner {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            email: Mutex::new(email.to_string()),
            verified: Mutex::new(verified),
            verified_text: Mutex::new(None),
            key,
            codes: Mutex::new(HashMap::new()),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let issuer = format!("http://127.0.0.1:{port}");
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(google_discovery))
            .route("/jwks", get(google_jwks))
            .route("/authorize", get(google_authorize))
            .route("/token", post(google_token))
            .with_state((issuer.clone(), inner.clone()));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            issuer,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            inner,
            task,
        }
    }

    pub fn set_account(&self, email: &str, verified: bool) {
        *self.inner.email.lock().unwrap_or_else(|e| e.into_inner()) = email.to_string();
        *self.inner.verified.lock().unwrap_or_else(|e| e.into_inner()) = verified;
        *self.inner.verified_text.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub fn set_verified_as_string(&self, email: &str, value: &str) {
        *self.inner.email.lock().unwrap_or_else(|e| e.into_inner()) = email.to_string();
        *self.inner.verified_text.lock().unwrap_or_else(|e| e.into_inner()) = Some(value.to_string());
    }
}

impl Drop for Google {
    fn drop(&mut self) {
        self.task.abort();
    }
}

type GoogleState = (String, Arc<GoogleInner>);

async fn google_discovery(State((issuer, _)): State<GoogleState>) -> impl IntoResponse {
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
}

async fn google_jwks(State((_, inner)): State<GoogleState>) -> impl IntoResponse {
    let public = RsaPublicKey::from(&inner.key);
    Json(json!({
        "keys": [{
            "kty": "RSA",
            "kid": "test",
            "use": "sig",
            "alg": "RS256",
            "n": b64(public.n().to_bytes_be()),
            "e": b64(public.e().to_bytes_be()),
        }]
    }))
}

#[derive(Deserialize)]
struct AuthQuery {
    client_id: String,
    response_type: String,
    code_challenge_method: String,
    code_challenge: String,
    state: String,
    nonce: String,
    redirect_uri: String,
}

async fn google_authorize(State((_, inner)): State<GoogleState>, Query(q): Query<AuthQuery>) -> impl IntoResponse {
    if q.client_id != inner.client_id || q.response_type != "code" || q.code_challenge_method != "S256" || q.code_challenge.is_empty() || q.state.is_empty() || q.nonce.is_empty() || q.redirect_uri.is_empty() {
        return (StatusCode::BAD_REQUEST, "bad authorize request").into_response();
    }
    let code = random_token();
    let email = inner.email.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let verified = match inner.verified_text.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        Some(text) => VerifiedClaim::Text(text),
        None => VerifiedClaim::Bool(*inner.verified.lock().unwrap_or_else(|e| e.into_inner())),
    };
    inner.codes.lock().unwrap_or_else(|e| e.into_inner()).insert(
        code.clone(),
        Pending {
            challenge: q.code_challenge,
            nonce: q.nonce.clone(),
            redirect: q.redirect_uri.clone(),
            email,
            verified,
        },
    );
    let Ok(mut dest) = url::Url::parse(&q.redirect_uri) else {
        return (StatusCode::BAD_REQUEST, "bad redirect").into_response();
    };
    dest.query_pairs_mut().append_pair("code", &code).append_pair("state", &q.state);
    (StatusCode::FOUND, [("location", dest.to_string())]).into_response()
}

async fn google_token(State((issuer, inner)): State<GoogleState>, headers: HeaderMap, body: axum::body::Bytes) -> impl IntoResponse {
    let form = form_pairs(&body);
    let (id, secret) = client_auth(&headers, &form);
    let code = form.get("code").cloned().unwrap_or_default();
    let pend = {
        let guard = inner.codes.lock().unwrap_or_else(|e| e.into_inner());
        guard.get(&code).map(|p| Pending {
            challenge: p.challenge.clone(),
            nonce: p.nonce.clone(),
            redirect: p.redirect.clone(),
            email: p.email.clone(),
            verified: match &p.verified {
                VerifiedClaim::Bool(v) => VerifiedClaim::Bool(*v),
                VerifiedClaim::Text(v) => VerifiedClaim::Text(v.clone()),
            },
        })
    };
    let Some(pend) = pend else {
        return (StatusCode::BAD_REQUEST, "bad code").into_response();
    };
    if id != inner.client_id || secret != inner.client_secret {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let redirect = form.get("redirect_uri").cloned().unwrap_or_default();
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    if redirect != pend.redirect || !pkce_ok(&verifier, &pend.challenge) {
        return (StatusCode::BAD_REQUEST, "bad code").into_response();
    }
    inner.codes.lock().unwrap_or_else(|e| e.into_inner()).remove(&code);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let email_verified = match pend.verified {
        VerifiedClaim::Bool(v) => Value::Bool(v),
        VerifiedClaim::Text(v) => Value::String(v),
    };
    let claims = json!({
        "iss": issuer,
        "aud": inner.client_id,
        "sub": "google-user",
        "iat": now,
        "exp": now + 3600,
        "nonce": pend.nonce,
        "email": pend.email,
        "email_verified": email_verified,
    });
    let raw = match sign_jwt(&inner.key, &claims) {
        Ok(raw) => raw,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err).into_response(),
    };
    Json(json!({
        "access_token": "google-access",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": raw,
    }))
    .into_response()
}

struct GhPending {
    challenge: String,
    redirect: String,
    emails: Vec<Email>,
}

struct GitHubInner {
    client_id: String,
    client_secret: String,
    emails: Mutex<Vec<Email>>,
    codes: Mutex<HashMap<String, GhPending>>,
    tokens: Mutex<HashMap<String, Vec<Email>>>,
}

pub struct GitHub {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub emails_url: String,
    task: JoinHandle<()>,
}

impl GitHub {
    pub async fn start(client_id: &str, client_secret: &str, emails: Vec<Email>) -> Self {
        let inner = Arc::new(GitHubInner {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            emails: Mutex::new(emails),
            codes: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let base = format!("http://127.0.0.1:{port}");
        let app = Router::new()
            .route("/authorize", get(github_authorize))
            .route("/token", post(github_token))
            .route("/user/emails", get(github_emails))
            .with_state(inner);
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: format!("{base}/authorize"),
            token_url: format!("{base}/token"),
            emails_url: format!("{base}/user/emails"),
            task,
        }
    }
}

impl Drop for GitHub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Deserialize)]
struct GhAuthQuery {
    client_id: String,
    code_challenge_method: String,
    code_challenge: String,
    state: String,
    redirect_uri: String,
}

async fn github_authorize(State(inner): State<Arc<GitHubInner>>, Query(q): Query<GhAuthQuery>) -> impl IntoResponse {
    if q.client_id != inner.client_id || q.code_challenge_method != "S256" || q.code_challenge.is_empty() || q.state.is_empty() || q.redirect_uri.is_empty() {
        return (StatusCode::BAD_REQUEST, "bad authorize request").into_response();
    }
    let code = random_token();
    let emails = inner.emails.lock().unwrap_or_else(|e| e.into_inner()).clone();
    inner.codes.lock().unwrap_or_else(|e| e.into_inner()).insert(
        code.clone(),
        GhPending {
            challenge: q.code_challenge,
            redirect: q.redirect_uri.clone(),
            emails,
        },
    );
    let Ok(mut dest) = url::Url::parse(&q.redirect_uri) else {
        return (StatusCode::BAD_REQUEST, "bad redirect").into_response();
    };
    dest.query_pairs_mut().append_pair("code", &code).append_pair("state", &q.state);
    (StatusCode::FOUND, [("location", dest.to_string())]).into_response()
}

async fn github_token(State(inner): State<Arc<GitHubInner>>, headers: HeaderMap, body: axum::body::Bytes) -> impl IntoResponse {
    let form = form_pairs(&body);
    let (id, secret) = client_auth(&headers, &form);
    if id.is_empty() {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let code = form.get("code").cloned().unwrap_or_default();
    let pend = {
        let guard = inner.codes.lock().unwrap_or_else(|e| e.into_inner());
        guard.get(&code).map(|p| GhPending {
            challenge: p.challenge.clone(),
            redirect: p.redirect.clone(),
            emails: p.emails.clone(),
        })
    };
    let Some(pend) = pend else {
        return (StatusCode::BAD_REQUEST, "bad code").into_response();
    };
    if id != inner.client_id || secret != inner.client_secret {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let redirect = form.get("redirect_uri").cloned().unwrap_or_default();
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    if redirect != pend.redirect || !pkce_ok(&verifier, &pend.challenge) {
        return (StatusCode::BAD_REQUEST, "bad code").into_response();
    }
    inner.codes.lock().unwrap_or_else(|e| e.into_inner()).remove(&code);
    let access = random_token();
    inner.tokens.lock().unwrap_or_else(|e| e.into_inner()).insert(access.clone(), pend.emails);
    Json(json!({
        "access_token": access,
        "token_type": "bearer",
        "scope": "user:email",
    }))
    .into_response()
}

async fn github_emails(State(inner): State<Arc<GitHubInner>>, headers: HeaderMap) -> impl IntoResponse {
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let Some(token) = auth.strip_prefix("Bearer ") else {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    };
    let emails = inner.tokens.lock().unwrap_or_else(|e| e.into_inner()).get(token).cloned();
    let Some(emails) = emails else {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    };
    let out: Vec<Value> = emails
        .into_iter()
        .map(|item| json!({"email": item.email, "primary": item.primary, "verified": item.verified}))
        .collect();
    Json(out).into_response()
}

fn client_auth(headers: &HeaderMap, form: &HashMap<String, String>) -> (String, String) {
    if let Some(id) = form.get("client_id") {
        if !id.is_empty() {
            return (id.clone(), form.get("client_secret").cloned().unwrap_or_default());
        }
    }
    let Some(raw) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return (String::new(), String::new());
    };
    let Some(encoded) = raw.strip_prefix("Basic ") else {
        return (String::new(), String::new());
    };
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
        return (String::new(), String::new());
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return (String::new(), String::new());
    };
    match text.split_once(':') {
        Some((id, secret)) => (id.to_string(), secret.to_string()),
        None => (String::new(), String::new()),
    }
}

fn form_pairs(body: &[u8]) -> HashMap<String, String> {
    form_urlencoded::parse(body).into_owned().collect()
}

fn pkce_ok(verifier: &str, challenge: &str) -> bool {
    let sum = Sha256::digest(verifier.as_bytes());
    b64(sum) == challenge
}

fn b64(bytes: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn random_token() -> String {
    let mut buf = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
    b64(buf)
}

fn sign_jwt(key: &RsaPrivateKey, claims: &Value) -> Result<String, String> {
    let pem = key.to_pkcs8_pem(LineEnding::LF).map_err(|e| e.to_string())?;
    let encoding = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| e.to_string())?;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test".into());
    jsonwebtoken::encode(&header, claims, &encoding).map_err(|e| e.to_string())
}
