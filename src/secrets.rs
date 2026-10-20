use std::net::IpAddr;
use std::time::Duration;

use crate::session::{self, KeyRing};

pub const DEFAULT_ISSUER: &str = "https://accounts.google.com";
pub const DEFAULT_GITHUB_AUTH: &str = "https://github.com/login/oauth/authorize";
pub const DEFAULT_GITHUB_TOKEN: &str = "https://github.com/login/oauth/access_token";
pub const DEFAULT_GITHUB_EMAIL: &str = "https://api.github.com/user/emails";
pub const DEFAULT_TTL: Duration = Duration::from_secs(12 * 60 * 60);

const MIN_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone)]
pub struct Secrets {
    pub google_id: String,
    pub google_secret: String,
    pub github_id: String,
    pub github_secret: String,
    pub keys: KeyRing,
    pub session_ttl: Duration,
    pub issuer: String,
    pub github_auth_url: String,
    pub github_token_url: String,
    pub github_emails_url: String,
    pub allow_unsafe: bool,
    pub listen: String,
}

impl Secrets {
    pub fn google_enabled(&self) -> bool {
        !self.google_id.is_empty() && !self.google_secret.is_empty()
    }

    pub fn github_enabled(&self) -> bool {
        !self.github_id.is_empty() && !self.github_secret.is_empty()
    }
}

pub fn from_env(getenv: impl Fn(&str) -> String) -> Result<Secrets, String> {
    let allow_unsafe = getenv("SHIP_ALLOW_UNSAFE_OAUTH_OVERRIDES") == "1";
    let issuer = nonempty(getenv("SHIP_OIDC_ISSUER"), DEFAULT_ISSUER);
    let gh_auth = nonempty(getenv("SHIP_GITHUB_AUTH_URL"), DEFAULT_GITHUB_AUTH);
    let gh_token = nonempty(getenv("SHIP_GITHUB_TOKEN_URL"), DEFAULT_GITHUB_TOKEN);
    let gh_emails = nonempty(getenv("SHIP_GITHUB_EMAILS_URL"), DEFAULT_GITHUB_EMAIL);
    if !allow_unsafe && (issuer != DEFAULT_ISSUER || gh_auth != DEFAULT_GITHUB_AUTH || gh_token != DEFAULT_GITHUB_TOKEN || gh_emails != DEFAULT_GITHUB_EMAIL) {
        return Err("refusing OAuth endpoint overrides without SHIP_ALLOW_UNSAFE_OAUTH_OVERRIDES=1".into());
    }
    for raw in [&issuer, &gh_auth, &gh_token, &gh_emails] {
        validate_endpoint(raw, allow_unsafe)?;
    }
    let google_id = getenv("SHIP_GOOGLE_CLIENT_ID").trim().to_string();
    let google_secret = getenv("SHIP_GOOGLE_CLIENT_SECRET");
    if google_id.is_empty() != google_secret.trim().is_empty() {
        return Err("set both SHIP_GOOGLE_CLIENT_ID and SHIP_GOOGLE_CLIENT_SECRET".into());
    }
    let github_id = getenv("SHIP_GITHUB_CLIENT_ID").trim().to_string();
    let github_secret = getenv("SHIP_GITHUB_CLIENT_SECRET");
    if github_id.is_empty() != github_secret.trim().is_empty() {
        return Err("set both SHIP_GITHUB_CLIENT_ID and SHIP_GITHUB_CLIENT_SECRET".into());
    }
    let key = getenv("SHIP_COOKIE_KEY");
    let prev = getenv("SHIP_COOKIE_KEY_PREVIOUS");
    let keys = session::KeyRing::new(&key, &prev).map_err(|e| format!("SHIP_COOKIE_KEY: {e}"))?;
    let raw_key = session::parse_key(&key)?;
    if raw_key.iter().all(|b| *b == 0) {
        return Err("SHIP_COOKIE_KEY is all zeros".into());
    }
    let ttl = match getenv("SHIP_SESSION_TTL").trim() {
        "" => DEFAULT_TTL,
        raw => humantime::parse_duration(raw).map_err(|e| format!("SHIP_SESSION_TTL: {e}"))?,
    };
    if ttl < MIN_TTL || ttl > MAX_TTL {
        return Err(format!("SHIP_SESSION_TTL must be between {MIN_TTL:?} and {MAX_TTL:?}"));
    }
    Ok(Secrets {
        google_id,
        google_secret,
        github_id,
        github_secret,
        keys,
        session_ttl: ttl,
        issuer,
        github_auth_url: gh_auth,
        github_token_url: gh_token,
        github_emails_url: gh_emails,
        allow_unsafe,
        listen: getenv("SHIP_LISTEN").trim().to_string(),
    })
}

fn nonempty(raw: String, default: &str) -> String {
    if raw.is_empty() {
        default.to_string()
    } else {
        raw
    }
}

fn validate_endpoint(raw: &str, allow_unsafe: bool) -> Result<(), String> {
    let u = url::Url::parse(raw).map_err(|_| format!("invalid OAuth endpoint {raw:?}"))?;
    if u.host_str().is_none() || !u.username().is_empty() || u.password().is_some() {
        return Err(format!("invalid OAuth endpoint {raw:?}"));
    }
    if u.scheme() == "https" {
        return Ok(());
    }
    let host = u.host_str().unwrap_or("");
    let ip = host.parse::<IpAddr>().ok();
    if allow_unsafe && u.scheme() == "http" && (host.eq_ignore_ascii_case("localhost") || ip.is_some_and(|ip| ip.is_loopback())) {
        return Ok(());
    }
    Err(format!("OAuth endpoint {raw:?} must be https"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn key(fill: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([fill; 32])
    }

    #[test]
    fn from_env_rules() {
        let ok = from_env(|k| match k {
            "SHIP_COOKIE_KEY" => key(2),
            "SHIP_GOOGLE_CLIENT_ID" => "gid".into(),
            "SHIP_GOOGLE_CLIENT_SECRET" => "gsec".into(),
            "SHIP_SESSION_TTL" => "30m".into(),
            _ => String::new(),
        })
        .unwrap();
        assert!(ok.google_enabled());
        assert!(!ok.github_enabled());
        assert_eq!(ok.session_ttl, Duration::from_secs(30 * 60));
        assert_eq!(ok.issuer, DEFAULT_ISSUER);
        assert!(!ok.allow_unsafe);
        assert!(from_env(|_| String::new()).is_err());
        assert!(from_env(|k| if k == "SHIP_COOKIE_KEY" { key(0) } else { String::new() }).is_err());
        assert!(from_env(|k| match k {
            "SHIP_COOKIE_KEY" => key(2),
            "SHIP_OIDC_ISSUER" => "https://evil.example".into(),
            _ => String::new(),
        })
        .is_err());
        let err = from_env(|k| match k {
            "SHIP_COOKIE_KEY" => key(2),
            "SHIP_ALLOW_UNSAFE_OAUTH_OVERRIDES" => "1".into(),
            "SHIP_OIDC_ISSUER" => "http://evil.example".into(),
            _ => String::new(),
        })
        .err()
        .expect("http issuer must be rejected");
        assert!(err.contains("https"), "{err}");
        let got = from_env(|k| match k {
            "SHIP_COOKIE_KEY" => key(2),
            "SHIP_ALLOW_UNSAFE_OAUTH_OVERRIDES" => "1".into(),
            "SHIP_OIDC_ISSUER" => "http://127.0.0.1:9999".into(),
            _ => String::new(),
        })
        .unwrap();
        assert_eq!(got.issuer, "http://127.0.0.1:9999");
    }
}
