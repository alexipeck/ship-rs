use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use base64::Engine;
use tower_http::timeout::TimeoutLayer;

use crate::config::{Access, Config, Store};
use crate::dnsname::{self, split_host_port};
use crate::identity;
use crate::oauth::{self, OauthError};
use crate::pages::{self, DenyView, LoginView};
use crate::returnurl;
use crate::secrets::Secrets;
use crate::session::{self, Session, SessionError};

#[derive(Clone)]
pub struct Service {
    pub store: Store,
    pub secrets: Secrets,
    oauth: oauth::Client,
    now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
}

impl Service {
    pub fn new(store: Store, secrets: Secrets) -> Self {
        let oauth = oauth::Client::new(oauth::Options {
            google_id: secrets.google_id.clone(),
            google_secret: secrets.google_secret.clone(),
            github_id: secrets.github_id.clone(),
            github_secret: secrets.github_secret.clone(),
            issuer: secrets.issuer.clone(),
            github_auth_url: secrets.github_auth_url.clone(),
            github_token_url: secrets.github_token_url.clone(),
            github_emails_url: secrets.github_emails_url.clone(),
        });
        Self {
            store,
            secrets,
            oauth,
            now: Arc::new(SystemTime::now),
        }
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/healthz", get(healthz))
            .route("/", get(home))
            .route("/login/{provider}", get(begin))
            .route("/callback/{provider}", get(finish))
            .route("/logout", post(logout).get(logout_help))
            .route("/check", get(check))
            .layer(axum::extract::DefaultBodyLimit::max(4096))
            .with_state(self.clone())
    }

    pub async fn run(self, addr: &str) -> Result<(), String> {
        require_loopback(addr)?;
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| e.to_string())?;
        let local = listener.local_addr().map_err(|e| e.to_string())?;
        if !local.ip().is_loopback() {
            return Err("refusing to listen on a non-loopback address".into());
        }
        tracing::info!(addr = %local, "listening");
        let app = self.router().layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(30)));
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(|e| e.to_string())
    }
}

pub fn require_loopback(addr: &str) -> Result<(), String> {
    let Some((host, port)) = split_host_port(addr) else {
        return Err("listen address must be host:port on loopback".into());
    };
    let n: u32 = port.parse().map_err(|_| "listen port is invalid".to_string())?;
    if !(1..=65535).contains(&n) {
        return Err("listen port is invalid".into());
    }
    if host.is_empty() {
        return Err("refusing to listen on all interfaces".into());
    }
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(());
    }
    let ip: IpAddr = host.parse().map_err(|_| "refusing to listen on a non-loopback address".to_string())?;
    if !ip.is_loopback() {
        return Err("refusing to listen on a non-loopback address".into());
    }
    let _ = SocketAddr::from((ip, n as u16));
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let term = async {
        if let Ok(mut sig) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            sig.recv().await;
        }
    };
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}

async fn healthz() -> Response {
    plain(StatusCode::OK, "ok\n")
}

async fn home(State(svc): State<Service>, headers: HeaderMap, uri: Uri) -> Response {
    let cfg = svc.store.current();
    let (ret, bad) = optional_return(&uri, &cfg);
    let status = if bad { StatusCode::BAD_REQUEST } else { StatusCode::OK };
    let mut email = String::new();
    let mut provider = String::new();
    if let Some(sess) = read_session(&svc, &headers) {
        email = sess.email;
        provider = identity::provider_label(&sess.provider).to_string();
    }
    let sign_out = if ret.is_empty() { cfg.hub_origin() } else { ret.clone() };
    let body = pages::login_page(&LoginView {
        google: svc.secrets.google_enabled(),
        github: svc.secrets.github_enabled(),
        ret: &ret,
        bad_return: bad,
        email: &email,
        provider: &provider,
        sign_out_return: &sign_out,
    });
    html(status, &pages::csp_self(), body)
}

async fn begin(State(svc): State<Service>, Path(provider): Path<String>, uri: Uri) -> Response {
    if provider != identity::PROVIDER_GOOGLE && provider != identity::PROVIDER_GITHUB {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let cfg = svc.store.current();
    if !provider_on(&svc, &provider) {
        return message(StatusCode::SERVICE_UNAVAILABLE, "Sign-in unavailable", &format!("{} sign-in is not configured.", identity::provider_label(&provider)));
    }
    let raw = query_param(&uri, "return");
    let ret = if raw.trim().is_empty() {
        cfg.hub_origin()
    } else {
        match returnurl::validate(raw.trim(), &cfg.base_domain) {
            Ok(v) => v,
            Err(_) => {
                tracing::info!("rejected return url");
                return message(StatusCode::BAD_REQUEST, "Sign in", "The return address is not allowed.");
            }
        }
    };
    let Ok(state) = random_string(32) else {
        return message(StatusCode::INTERNAL_SERVER_ERROR, "Sign in", "Sign-in could not be completed.");
    };
    let Ok(nonce) = random_string(32) else {
        return message(StatusCode::INTERNAL_SERVER_ERROR, "Sign in", "Sign-in could not be completed.");
    };
    let Ok(verifier) = random_string(32) else {
        return message(StatusCode::INTERNAL_SERVER_ERROR, "Sign in", "Sign-in could not be completed.");
    };
    let exp = (svc.now)() + Duration::from_secs(10 * 60);
    let sealed = match svc.secrets.keys.seal_oauth(&session::OAuthState {
        state: state.clone(),
        verifier: verifier.clone(),
        nonce: nonce.clone(),
        provider: provider.clone(),
        return_to: ret,
        expires: exp,
    }) {
        Ok(v) => v,
        Err(_) => return message(StatusCode::INTERNAL_SERVER_ERROR, "Sign in", "Sign-in could not be completed."),
    };
    let redirect = format!("{}{}", cfg.auth_origin(), callback_path(&provider));
    let auth_url = match svc.oauth.auth_url(&provider, &redirect, &state, &verifier, &nonce).await {
        Ok(v) => v,
        Err(err) => {
            let reference = new_ref();
            tracing::error!(reference, error = %err, "login start failed");
            return message(StatusCode::BAD_GATEWAY, "Sign in", &format!("Sign-in could not be completed. Reference {reference}."));
        }
    };
    redirect_found(&auth_url, &[session::oauth_cookie(&sealed)])
}

async fn finish(State(svc): State<Service>, Path(provider): Path<String>, headers: HeaderMap, uri: Uri) -> Response {
    if provider != identity::PROVIDER_GOOGLE && provider != identity::PROVIDER_GITHUB {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let cfg = svc.store.current();
    let err = query_param(&uri, "error");
    if !err.is_empty() {
        let page = if err == "access_denied" {
            message(StatusCode::BAD_REQUEST, "Sign in", "Sign-in was cancelled.")
        } else {
            message(StatusCode::BAD_REQUEST, "Sign in", "Sign-in could not be completed.")
        };
        return with_cookies(page, &[session::clear_oauth_cookie()]);
    }
    let code = query_param(&uri, "code");
    let state = query_param(&uri, "state");
    if code.is_empty() || state.is_empty() || code.len() > 2048 || state.len() > 512 {
        let page = message(StatusCode::BAD_REQUEST, "Sign in", "Sign-in could not be completed.");
        return with_cookies(page, &[session::clear_oauth_cookie()]);
    }
    let Some(raw_cookie) = cookie_value(&headers, session::OAUTH_COOKIE_NAME) else {
        return message(StatusCode::BAD_REQUEST, "Sign in", "Sign-in could not be completed.");
    };
    let opened = svc.secrets.keys.open_oauth(&raw_cookie, (svc.now)());
    let page_clear = session::clear_oauth_cookie();
    let st = match opened {
        Ok(st) if st.provider == provider && session::const_eq(&st.state, &state) => st,
        _ => {
            let page = message(StatusCode::BAD_REQUEST, "Sign in", "Sign-in could not be completed.");
            return with_cookies(page, &[page_clear]);
        }
    };
    let ret = match returnurl::validate(&st.return_to, &cfg.base_domain) {
        Ok(v) => v,
        Err(_) => {
            let page = message(StatusCode::BAD_REQUEST, "Sign in", "The return address is not allowed.");
            return with_cookies(page, &[page_clear]);
        }
    };
    let redirect = format!("{}{}", cfg.auth_origin(), callback_path(&provider));
    let email = match svc.oauth.complete(&provider, &redirect, &code, &st.verifier, &st.nonce).await {
        Ok(email) => email,
        Err(err) => {
            let page = login_error(err);
            return with_cookies(page, &[page_clear]);
        }
    };
    let issued = (svc.now)();
    let sealed = match svc.secrets.keys.seal_session(&Session {
        email: email.clone(),
        provider: provider.clone(),
        issued,
        expires: issued + svc.secrets.session_ttl,
    }) {
        Ok(v) => v,
        Err(_) => {
            let page = message(StatusCode::INTERNAL_SERVER_ERROR, "Sign in", "Sign-in could not be completed.");
            return with_cookies(page, &[page_clear]);
        }
    };
    tracing::info!(provider = %provider, email = %email, "login");
    redirect_found(&ret, &[page_clear, session::session_cookie(&cfg.base_domain, &sealed, svc.secrets.session_ttl)])
}

async fn logout(State(svc): State<Service>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let cfg = svc.store.current();
    if body.len() > 4096 {
        return plain(StatusCode::BAD_REQUEST, "bad request\n");
    }
    let ct = header_value(&headers, header::CONTENT_TYPE.as_str());
    if !is_form(&ct) {
        return plain(StatusCode::BAD_REQUEST, "bad request\n");
    }
    if !origin_allowed(&headers, &cfg.base_domain) {
        return plain(StatusCode::FORBIDDEN, "bad origin\n");
    }
    let form: std::collections::HashMap<String, String> = form_urlencoded::parse(&body).into_owned().collect();
    let mut ret = cfg.hub_origin();
    if let Some(raw) = form.get("return") {
        if !raw.is_empty() {
            if let Ok(dest) = returnurl::validate(raw, &cfg.base_domain) {
                ret = dest;
            }
        }
    }
    redirect_see_other(&ret, &[session::clear_session_cookie(&cfg.base_domain)])
}

async fn logout_help() -> Response {
    message(StatusCode::METHOD_NOT_ALLOWED, "Sign out", "Use the sign-out button.")
}

async fn check(State(svc): State<Service>, headers: HeaderMap) -> Response {
    let cfg = svc.store.current();
    let host = clip(&header_value(&headers, "x-forwarded-host"));
    let sess = read_session(&svc, &headers);
    let signed_in = sess.is_some();
    let email = sess.as_ref().map(|s| s.email.clone()).unwrap_or_default();
    let (site, access) = cfg.authorize(&host, &email, signed_in);
    let html_wanted = wants_html(&headers);
    match access {
        Access::Public => Response::builder().status(StatusCode::OK).header("cache-control", "no-store").body(Body::empty()).unwrap(),
        Access::Allowed => {
            tracing::info!(host = %host, result = "allow", "check");
            Response::builder()
                .status(StatusCode::OK)
                .header("cache-control", "no-store")
                .header("x-ship-rs-email", email)
                .body(Body::empty())
                .unwrap()
        }
        Access::Anonymous => {
            tracing::info!(host = %host, result = "anonymous", "check");
            if !html_wanted {
                return plain(StatusCode::UNAUTHORIZED, "401 Sign in required\n");
            }
            sign_in_required(&headers, &cfg, site.as_ref().map(|s| s.title.as_str()).unwrap_or("This site"))
        }
        Access::Denied => {
            tracing::info!(host = %host, result = "deny", email = %email, "check");
            if !html_wanted {
                return plain(StatusCode::FORBIDDEN, "403 Access denied\n");
            }
            let sess = sess.unwrap_or(Session {
                email: email.clone(),
                provider: String::new(),
                issued: UNIX_FALLBACK,
                expires: UNIX_FALLBACK,
            });
            access_denied(&headers, &cfg, site.as_ref().map(|s| s.title.as_str()).unwrap_or("This site"), &sess)
        }
        Access::Unknown | Access::Disabled => {
            tracing::info!(host = %host, result = "unavailable", "check");
            if !html_wanted {
                return plain(StatusCode::FORBIDDEN, "403 Access denied\n");
            }
            message(StatusCode::FORBIDDEN, "Unavailable", "This site is not available.")
        }
    }
}

const UNIX_FALLBACK: SystemTime = SystemTime::UNIX_EPOCH;

fn sign_in_required(headers: &HeaderMap, cfg: &Config, title: &str) -> Response {
    let mut target = format!("{}/", cfg.auth_origin());
    if let Ok(orig) = original_url(headers, &cfg.base_domain) {
        target = format!("{}/?return={}", cfg.auth_origin(), query_escape(&orig));
    }
    html(StatusCode::UNAUTHORIZED, &pages::csp_auth(&cfg.auth_origin()), pages::sign_in_page(title, &target))
}

fn access_denied(headers: &HeaderMap, cfg: &Config, title: &str, sess: &Session) -> Response {
    let mut sign_out = cfg.hub_origin();
    let mut switch_to = format!("{}/", cfg.auth_origin());
    if let Ok(orig) = original_url(headers, &cfg.base_domain) {
        sign_out = orig.clone();
        switch_to = format!("{}/?return={}", cfg.auth_origin(), query_escape(&orig));
    }
    html(
        StatusCode::FORBIDDEN,
        &pages::csp_auth(&cfg.auth_origin()),
        pages::deny_page(&DenyView {
            title,
            email: &sess.email,
            provider: identity::provider_label(&sess.provider),
            logout_url: &format!("{}/logout", cfg.auth_origin()),
            sign_out_return: &sign_out,
            switch_return: &switch_to,
        }),
    )
}

fn login_error(err: OauthError) -> Response {
    match err {
        OauthError::EmailUnverified => message(StatusCode::BAD_REQUEST, "Sign in", "That account's email is not verified."),
        OauthError::NoPrimaryEmail => message(StatusCode::BAD_REQUEST, "Sign in", "GitHub did not provide a verified primary email."),
        other => {
            let reference = new_ref();
            tracing::error!(reference, error = %other, "login failed");
            message(StatusCode::BAD_GATEWAY, "Sign in", &format!("Sign-in could not be completed. Reference {reference}."))
        }
    }
}

fn read_session(svc: &Service, headers: &HeaderMap) -> Option<Session> {
    let value = cookie_value(headers, session::SESSION_COOKIE_NAME)?;
    match svc.secrets.keys.open_session(&value, (svc.now)(), svc.secrets.session_ttl) {
        Ok(sess) => Some(sess),
        Err(SessionError::Expired) => {
            tracing::info!("session expired");
            None
        }
        Err(_) => {
            tracing::info!("session rejected");
            None
        }
    }
}

fn optional_return(uri: &Uri, cfg: &Config) -> (String, bool) {
    let raw = query_param(uri, "return");
    let raw = raw.trim();
    if raw.is_empty() {
        return (String::new(), false);
    }
    match returnurl::validate(raw, &cfg.base_domain) {
        Ok(v) => (v, false),
        Err(_) => (String::new(), true),
    }
}

fn provider_on(svc: &Service, provider: &str) -> bool {
    match provider {
        identity::PROVIDER_GOOGLE => svc.secrets.google_enabled(),
        identity::PROVIDER_GITHUB => svc.secrets.github_enabled(),
        _ => false,
    }
}

fn original_url(headers: &HeaderMap, base: &str) -> Result<String, ()> {
    let proto = header_value(headers, "x-forwarded-proto").trim().to_ascii_lowercase();
    let host = header_value(headers, "x-forwarded-host").trim().to_string();
    let uri = header_value(headers, "x-forwarded-uri");
    if proto.is_empty() || host.is_empty() || uri.is_empty() {
        return Err(());
    }
    if proto.chars().any(|c| matches!(c, ' ' | '\t' | '\r' | '\n' | '/')) || host.chars().any(|c| matches!(c, ' ' | '\t' | '\r' | '\n' | '/')) || uri.chars().any(|c| matches!(c, '\r' | '\n' | '\\')) {
        return Err(());
    }
    if !uri.starts_with('/') || uri.starts_with("//") {
        return Err(());
    }
    returnurl::validate(&format!("{proto}://{host}{uri}"), base).map_err(|_| ())
}

fn origin_allowed(headers: &HeaderMap, base: &str) -> bool {
    let mut raw = header_value(headers, "origin");
    if raw.is_empty() {
        raw = header_value(headers, "referer");
    }
    if raw.is_empty() {
        return false;
    }
    let Ok(u) = url::Url::parse(&raw) else {
        return false;
    };
    if u.scheme() != "https" || u.host_str().is_none() || !u.username().is_empty() || u.password().is_some() {
        return false;
    }
    dnsname::allowed(u.host_str().unwrap_or(""), base)
}

fn wants_html(headers: &HeaderMap) -> bool {
    match header_value(headers, "sec-fetch-dest").to_ascii_lowercase().as_str() {
        "document" | "iframe" => return true,
        "image" | "script" | "style" | "font" | "audio" | "video" | "object" | "embed" | "worker" | "manifest" | "empty" => return false,
        _ => {}
    }
    accepts_html(&header_value(headers, "accept"))
}

fn accepts_html(accept: &str) -> bool {
    if accept.trim().is_empty() {
        return false;
    }
    for part in accept.split(',') {
        let media = part.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        if media == "text/html" || media == "application/xhtml+xml" {
            return true;
        }
    }
    false
}

fn html(status: StatusCode, csp: &str, body: String) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .header("x-frame-options", "DENY")
        .header("content-security-policy", csp)
        .body(Body::from(body))
        .unwrap()
}

fn message(status: StatusCode, title: &str, text: &str) -> Response {
    html(status, pages::csp_self(), pages::message_page(title, text))
}

fn plain(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn redirect_found(loc: &str, cookies: &[cookie::Cookie<'static>]) -> Response {
    redirect(StatusCode::FOUND, loc, cookies)
}

fn redirect_see_other(loc: &str, cookies: &[cookie::Cookie<'static>]) -> Response {
    redirect(StatusCode::SEE_OTHER, loc, cookies)
}

fn redirect(status: StatusCode, loc: &str, cookies: &[cookie::Cookie<'static>]) -> Response {
    let mut res = Response::builder().status(status).header("location", loc).header("cache-control", "no-store");
    for c in cookies {
        res = res.header("set-cookie", c.to_string());
    }
    res.body(Body::empty()).unwrap()
}

fn with_cookies(mut res: Response, cookies: &[cookie::Cookie<'static>]) -> Response {
    for c in cookies {
        res.headers_mut().append("set-cookie", header::HeaderValue::from_str(&c.to_string()).unwrap_or(header::HeaderValue::from_static("")));
    }
    res
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        let (k, v) = part.split_once('=')?;
        if k.trim() == name {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn query_param(uri: &Uri, key: &str) -> String {
    let Some(q) = uri.query() else {
        return String::new();
    };
    form_urlencoded::parse(q.as_bytes()).find(|(k, _)| k == key).map(|(_, v)| v.into_owned()).unwrap_or_default()
}

fn query_escape(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn header_value(headers: &HeaderMap, name: &str) -> String {
    headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

fn is_form(ct: &str) -> bool {
    ct.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/x-www-form-urlencoded")
}

fn callback_path(provider: &str) -> String {
    format!("/callback/{provider}")
}

fn random_string(n: usize) -> Result<String, ()> {
    let mut buf = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

fn new_ref() -> String {
    let mut buf = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
    hex::encode(buf)
}

fn clip(s: &str) -> String {
    s.chars().filter(|c| *c != '\n' && *c != '\r').take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use axum::http::Request;
    use base64::Engine;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn sample_toml() -> &'static str {
        r#"
base_domain = "example.com"
tls = "internal"
auth_upstream = "127.0.0.1:8091"
caddyfile = "Caddyfile"
admins = ["Owner@Example.com"]

[hub]
title = "Example sites"
deploy = "hub"

[[sites]]
slug = "hello"
title = "Public hello"
deploy = "hello"
subdomain = "hello"
public = true

[[sites]]
slug = "notes"
title = "Protected hello"
deploy = "notes"
subdomain = "notes"
public = false
allow = ["Guest@Example.com"]
"#
    }

    fn write_config(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sites.toml");
        std::fs::write(&path, body).unwrap();
        (dir, path)
    }

    fn test_secrets(extra: &[(&str, &str)]) -> Secrets {
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        crate::secrets::from_env(|k| {
            for (name, value) in extra {
                if *name == k {
                    return (*value).to_string();
                }
            }
            match k {
                "SHIP_COOKIE_KEY" => key.clone(),
                "SHIP_GOOGLE_CLIENT_ID" => "test-google-id".into(),
                "SHIP_GOOGLE_CLIENT_SECRET" => "test-google-secret".into(),
                "SHIP_GITHUB_CLIENT_ID" => "test-github-id".into(),
                "SHIP_GITHUB_CLIENT_SECRET" => "test-github-secret".into(),
                "SHIP_ALLOW_UNSAFE_OAUTH_OVERRIDES" => "1".into(),
                _ => String::new(),
            }
        })
        .unwrap()
    }

    fn new_svc(path: &std::path::Path) -> Service {
        let store = config::Store::open(path).unwrap();
        Service::new(store, test_secrets(&[]))
    }

    fn mint(svc: &Service, email: &str, provider: &str, expires: Option<SystemTime>) -> String {
        let issued = SystemTime::now() - Duration::from_secs(2 * 3600);
        let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(issued.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());
        let expires = expires.unwrap_or(issued + svc.secrets.session_ttl);
        svc.secrets
            .keys
            .seal_session(&Session {
                email: email.into(),
                provider: provider.into(),
                issued,
                expires,
            })
            .unwrap()
    }

    fn check_req(host: &str, uri: &str, cookie: &str, accept: &str, dest: &str) -> Request<Body> {
        let mut b = Request::builder().method("GET").uri("/check").header("x-forwarded-proto", "https").header("x-forwarded-host", host).header("x-forwarded-uri", uri);
        if !accept.is_empty() {
            b = b.header("accept", accept);
        }
        if !dest.is_empty() {
            b = b.header("sec-fetch-dest", dest);
        }
        if !cookie.is_empty() {
            b = b.header("cookie", format!("{}={cookie}", session::SESSION_COOKIE_NAME));
        }
        b.body(Body::empty()).unwrap()
    }

    async fn do_req(app: Router, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
    }

    fn set_cookie_value(headers: &HeaderMap, name: &str) -> String {
        let mut found = String::new();
        for value in headers.get_all("set-cookie") {
            let s = value.to_str().unwrap();
            let Some((n, rest)) = s.split_once('=') else { continue };
            if n == name {
                let v = rest.split(';').next().unwrap_or("");
                if !v.is_empty() {
                    found = v.to_string();
                }
            }
        }
        assert!(!found.is_empty(), "missing cookie {name} in {headers:?}");
        found
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn check_allowlist_cookies_and_reload() {
        let (_dir, path) = write_config(sample_toml());
        let svc = new_svc(&path);
        let guest = mint(&svc, "guest@example.com", identity::PROVIDER_GOOGLE, None);
        let admin = mint(&svc, "owner@example.com", identity::PROVIDER_GITHUB, None);
        let stranger = mint(&svc, "stranger@example.com", identity::PROVIDER_GOOGLE, None);

        let (status, headers, body) = do_req(svc.router(), check_req("notes.example.com", "/docs", "", "text/html", "document")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(headers.get("location").is_none());
        assert!(body.contains("Sign in"));
        assert!(!body.contains("http-equiv"));
        assert!(!body.contains("location.href"));
        assert!(body.contains("https://auth.example.com/?return="), "{body}");

        let (status, _, body) = do_req(svc.router(), check_req("notes.example.com", "/docs", "", "application/json", "")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, "401 Sign in required\n");

        let (status, headers, _) = do_req(svc.router(), check_req("notes.example.com", "/docs", &guest, "text/html", "document")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get("x-ship-rs-email").unwrap(), "guest@example.com");

        let (status, _, _) = do_req(svc.router(), check_req("notes.example.com", "/docs", &admin, "text/html", "document")).await;
        assert_eq!(status, StatusCode::OK);

        let mut req = check_req("notes.example.com", "/docs", &stranger, "text/html", "document");
        req.headers_mut().insert("x-ship-rs-email", "owner@example.com".parse().unwrap());
        let (status, _, body) = do_req(svc.router(), req).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("stranger@example.com"), "{body}");

        let (status, _, body) = do_req(svc.router(), check_req("notes.example.com", "/docs", &stranger, "application/json", "empty")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!body.contains("<html"));
        assert!(!body.contains("stranger@example.com"));
        assert_eq!(body, "403 Access denied\n");

        let mut raw = base64::engine::general_purpose::STANDARD.decode(&guest).unwrap();
        raw[20] ^= 0xff;
        let tampered = base64::engine::general_purpose::STANDARD.encode(raw);
        let (status, _, _) = do_req(svc.router(), check_req("notes.example.com", "/", &tampered, "text/html", "document")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let unsigned = base64::engine::general_purpose::STANDARD.encode(br#"{"email":"owner@example.com","provider":"google","iat":1,"exp":9999999999}"#);
        let (status, _, _) = do_req(svc.router(), check_req("notes.example.com", "/", &unsigned, "application/json", "")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let expired = mint(&svc, "owner@example.com", identity::PROVIDER_GOOGLE, Some(SystemTime::now() - Duration::from_secs(3600)));
        let (status, _, _) = do_req(svc.router(), check_req("notes.example.com", "/", &expired, "application/json", "")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let removed = sample_toml().replace(r#"allow = ["Guest@Example.com"]"#, "allow = []");
        std::fs::write(&path, removed).unwrap();
        let (status, _, _) = do_req(svc.router(), check_req("notes.example.com", "/", &guest, "application/json", "")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = do_req(svc.router(), check_req("notes.example.com", "/", &admin, "application/json", "")).await;
        assert_eq!(status, StatusCode::OK);
        std::fs::write(&path, "{ not toml").unwrap();
        let (status, _, _) = do_req(svc.router(), check_req("notes.example.com", "/", &admin, "application/json", "")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = do_req(svc.router(), check_req("notes.example.com", "/", &guest, "application/json", "")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, headers, _) = do_req(svc.router(), check_req("hello.example.com", "/", "", "text/html", "document")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(headers.get("x-ship-rs-email").is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn login_rejects_open_redirect() {
        let (_dir, path) = write_config(sample_toml());
        let svc = new_svc(&path);
        let req = Request::builder()
            .uri(format!("/login/google?return={}", query_escape("https://evil.com/phish")))
            .body(Body::empty())
            .unwrap();
        let (status, headers, body) = do_req(svc.router(), req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(headers.get("location").is_none());
        assert!(!body.contains("evil.com"), "{body}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn google_login_sets_session() {
        let idp = crate::testidp::Google::start("test-google-id", "test-google-secret", "Guest@Example.com", true).await;
        let (_dir, path) = write_config(sample_toml());
        let store = config::Store::open(&path).unwrap();
        let svc = Service::new(store, test_secrets(&[("SHIP_OIDC_ISSUER", &idp.issuer)]));
        let ret = "https://notes.example.com/docs?x=1";
        let req = Request::builder()
            .uri(format!("/login/google?return={}", query_escape(ret)))
            .body(Body::empty())
            .unwrap();
        let (status, headers, body) = do_req(svc.router(), req).await;
        assert_eq!(status, StatusCode::FOUND, "{body}");
        let oauth_cookie = set_cookie_value(&headers, session::OAUTH_COOKIE_NAME);
        let loc = headers.get("location").unwrap().to_str().unwrap().to_string();
        let parsed = url::Url::parse(&loc).unwrap();
        assert_eq!(parsed.query_pairs().find(|(k, _)| k == "code_challenge_method").unwrap().1, "S256");
        assert!(parsed.query_pairs().any(|(k, v)| k == "nonce" && !v.is_empty()));
        let idp_res = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
            .get(loc)
            .send()
            .await
            .unwrap();
        let back = idp_res.headers().get("location").unwrap().to_str().unwrap().to_string();
        let back_url = url::Url::parse(&back).unwrap();
        let code = back_url.query_pairs().find(|(k, _)| k == "code").unwrap().1.into_owned();
        let state = back_url.query_pairs().find(|(k, _)| k == "state").unwrap().1.into_owned();
        let cb = Request::builder()
            .uri(format!("/callback/google?code={}&state={}", query_escape(&code), query_escape(&state)))
            .header("cookie", format!("{}={oauth_cookie}", session::OAUTH_COOKIE_NAME))
            .body(Body::empty())
            .unwrap();
        let (status, headers, body) = do_req(svc.router(), cb).await;
        assert_eq!(status, StatusCode::FOUND, "{body}");
        assert_eq!(headers.get("location").unwrap(), ret);
        let session_cookie = set_cookie_value(&headers, session::SESSION_COOKIE_NAME);
        let joined = headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        for want in ["HttpOnly", "Secure", "SameSite=Lax", "Domain=example.com"] {
            assert!(joined.contains(want), "{joined}");
        }
        let (status, headers, _) = do_req(svc.router(), check_req("notes.example.com", "/docs?x=1", &session_cookie, "text/html", "document")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get("x-ship-rs-email").unwrap(), "guest@example.com");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn logout_origin() {
        let (_dir, path) = write_config(sample_toml());
        let svc = new_svc(&path);
        let bad = Request::builder()
            .method("POST")
            .uri("/logout")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", "https://evil.com")
            .body(Body::from(format!("return={}", query_escape("https://evil.com/"))))
            .unwrap();
        let (status, headers, _) = do_req(svc.router(), bad).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(headers.get("set-cookie").is_none());
        let good = Request::builder()
            .method("POST")
            .uri("/logout")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", "https://notes.example.com")
            .body(Body::from(format!("return={}", query_escape("https://notes.example.com/docs"))))
            .unwrap();
        let (status, headers, _) = do_req(svc.router(), good).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(headers.get("location").unwrap(), "https://notes.example.com/docs");
        let set = headers.get("set-cookie").unwrap().to_str().unwrap();
        assert!(set.contains("Max-Age=0") || set.contains("Max-Age=-1"), "{set}");
    }

    #[test]
    fn listen_loopback_only() {
        assert!(require_loopback("0.0.0.0:8091").is_err());
        assert!(require_loopback(":8091").is_err());
        assert!(require_loopback("192.0.2.10:1").is_err());
        assert!(require_loopback("127.0.0.1:8091").is_ok());
        assert!(require_loopback("localhost:8091").is_ok());
        assert!(require_loopback("[::1]:8091").is_ok());
    }
}
