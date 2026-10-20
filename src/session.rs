use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use cookie::time::Duration as CookieDuration;
use cookie::{Cookie, CookieJar, Key, SameSite};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::identity;

pub const SESSION_COOKIE_NAME: &str = "ship-rs_session";
pub const OAUTH_COOKIE_NAME: &str = "__Host-ship-rs_oauth";

const OAUTH_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_SEAL_TTL: Duration = Duration::from_secs(8 * 24 * 60 * 60);
const SKEW: i64 = 30;
const FUTURE_SKEW: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("unauthenticated")]
    Unauthenticated,
    #[error("expired")]
    Expired,
    #[error("invalid session")]
    Invalid,
}

#[derive(Clone)]
pub struct KeyRing {
    current: [u8; 32],
    previous: Option<[u8; 32]>,
}

pub fn parse_key(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty cookie key".into());
    }
    for engine in [base64::engine::general_purpose::STANDARD, base64::engine::general_purpose::STANDARD_NO_PAD] {
        if let Ok(b) = engine.decode(s) {
            if b.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&b);
                return Ok(out);
            }
        }
    }
    if let Ok(b) = hex::decode(s) {
        if b.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&b);
            return Ok(out);
        }
    }
    Err("cookie key must decode to 32 bytes".into())
}

impl KeyRing {
    pub fn new(current: &str, previous: &str) -> Result<Self, String> {
        let current = parse_key(current)?;
        let previous = if previous.trim().is_empty() {
            None
        } else {
            Some(parse_key(previous)?)
        };
        Ok(Self { current, previous })
    }

    pub fn seal_session(&self, session: &Session) -> Result<String, SessionError> {
        let email = identity::normalize_email(&session.email).map_err(|_| SessionError::Invalid)?;
        if !identity::valid_provider(&session.provider) {
            return Err(SessionError::Invalid);
        }
        let iat = unix(&session.issued).ok_or(SessionError::Invalid)?;
        let exp = unix(&session.expires).ok_or(SessionError::Invalid)?;
        let life = exp - iat;
        if life <= 0 || life > MAX_SEAL_TTL.as_secs() as i64 {
            return Err(SessionError::Invalid);
        }
        let wire = SessionWire {
            email,
            provider: session.provider.clone(),
            iat,
            exp,
        };
        let plain = serde_json::to_string(&wire).map_err(|_| SessionError::Invalid)?;
        self.seal(SESSION_COOKIE_NAME, &plain)
    }

    pub fn open_session(&self, token: &str, now: SystemTime, max_ttl: Duration) -> Result<Session, SessionError> {
        let plain = self.open(SESSION_COOKIE_NAME, token)?;
        let wire: SessionWire = serde_json::from_str(&plain).map_err(|_| SessionError::Unauthenticated)?;
        let email = identity::normalize_email(&wire.email).map_err(|_| SessionError::Unauthenticated)?;
        if !identity::valid_provider(&wire.provider) {
            return Err(SessionError::Unauthenticated);
        }
        let life = wire.exp - wire.iat;
        let max = max_ttl.as_secs() as i64 + FUTURE_SKEW;
        if life <= 0 || life > max {
            return Err(SessionError::Unauthenticated);
        }
        let now = unix(&now).ok_or(SessionError::Unauthenticated)?;
        if wire.iat > now + FUTURE_SKEW {
            return Err(SessionError::Unauthenticated);
        }
        if now >= wire.exp + SKEW {
            return Err(SessionError::Expired);
        }
        Ok(Session {
            email,
            provider: wire.provider,
            issued: UNIX_EPOCH + Duration::from_secs(wire.iat as u64),
            expires: UNIX_EPOCH + Duration::from_secs(wire.exp as u64),
        })
    }

    pub fn seal_oauth(&self, state: &OAuthState) -> Result<String, SessionError> {
        if state.state.is_empty()
            || state.verifier.is_empty()
            || state.provider.is_empty()
            || state.return_to.is_empty()
            || !identity::valid_provider(&state.provider)
        {
            return Err(SessionError::Invalid);
        }
        let exp = unix(&state.expires).ok_or(SessionError::Invalid)?;
        let wire = OauthWire {
            state: state.state.clone(),
            verifier: state.verifier.clone(),
            nonce: state.nonce.clone(),
            provider: state.provider.clone(),
            return_to: state.return_to.clone(),
            exp,
        };
        let plain = serde_json::to_string(&wire).map_err(|_| SessionError::Invalid)?;
        self.seal(OAUTH_COOKIE_NAME, &plain)
    }

    pub fn open_oauth(&self, token: &str, now: SystemTime) -> Result<OAuthState, SessionError> {
        let plain = self.open(OAUTH_COOKIE_NAME, token)?;
        let wire: OauthWire = serde_json::from_str(&plain).map_err(|_| SessionError::Unauthenticated)?;
        if wire.state.is_empty() || wire.verifier.is_empty() || wire.return_to.is_empty() || !identity::valid_provider(&wire.provider) {
            return Err(SessionError::Unauthenticated);
        }
        let now = unix(&now).ok_or(SessionError::Unauthenticated)?;
        if now >= wire.exp + SKEW {
            return Err(SessionError::Expired);
        }
        if wire.exp > now + OAUTH_TTL.as_secs() as i64 + FUTURE_SKEW {
            return Err(SessionError::Unauthenticated);
        }
        Ok(OAuthState {
            state: wire.state,
            verifier: wire.verifier,
            nonce: wire.nonce,
            provider: wire.provider,
            return_to: wire.return_to,
            expires: UNIX_EPOCH + Duration::from_secs(wire.exp as u64),
        })
    }

    fn seal(&self, name: &str, plain: &str) -> Result<String, SessionError> {
        let mut jar = CookieJar::new();
        let key = key(&self.current);
        jar.private_mut(&key).add(Cookie::new(name.to_string(), plain.to_string()));
        jar.get(name)
            .map(|c| c.value().to_string())
            .ok_or(SessionError::Invalid)
    }

    fn open(&self, name: &str, token: &str) -> Result<String, SessionError> {
        if token.is_empty() || token.len() > 4096 {
            return Err(SessionError::Unauthenticated);
        }
        let mut keys = vec![self.current];
        if let Some(prev) = self.previous {
            keys.push(prev);
        }
        for raw in keys {
            let key = key(&raw);
            let mut jar = CookieJar::new();
            jar.add_original(Cookie::new(name.to_string(), token.to_string()));
            if let Some(c) = jar.private(&key).get(name) {
                return Ok(c.value().to_string());
            }
        }
        Err(SessionError::Unauthenticated)
    }
}

#[derive(Clone, Debug)]
pub struct Session {
    pub email: String,
    pub provider: String,
    pub issued: SystemTime,
    pub expires: SystemTime,
}

#[derive(Clone, Debug)]
pub struct OAuthState {
    pub state: String,
    pub verifier: String,
    pub nonce: String,
    pub provider: String,
    pub return_to: String,
    pub expires: SystemTime,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionWire {
    email: String,
    provider: String,
    iat: i64,
    exp: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OauthWire {
    state: String,
    verifier: String,
    nonce: String,
    provider: String,
    #[serde(rename = "return")]
    return_to: String,
    exp: i64,
}

pub fn session_cookie(base_domain: &str, value: &str, ttl: Duration) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, value.to_string()))
        .path("/")
        .domain(base_domain.to_string())
        .max_age(CookieDuration::seconds(ttl.as_secs() as i64))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build()
}

pub fn clear_session_cookie(base_domain: &str) -> Cookie<'static> {
    let mut c = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .domain(base_domain.to_string())
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();
    c.make_removal();
    c
}

pub fn oauth_cookie(value: &str) -> Cookie<'static> {
    Cookie::build((OAUTH_COOKIE_NAME, value.to_string()))
        .path("/")
        .max_age(CookieDuration::seconds(OAUTH_TTL.as_secs() as i64))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build()
}

pub fn clear_oauth_cookie() -> Cookie<'static> {
    let mut c = Cookie::build((OAUTH_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();
    c.make_removal();
    c
}

pub fn const_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn key(raw: &[u8; 32]) -> Key {
    Key::derive_from(raw)
}

fn unix(t: &SystemTime) -> Option<i64> {
    let d = t.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(d.as_secs()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::collections::BTreeSet;

    fn make_ring(fill: u8) -> KeyRing {
        let key = base64::engine::general_purpose::STANDARD.encode([fill; 32]);
        KeyRing::new(&key, "").unwrap()
    }

    #[test]
    fn round_trip_and_rejection() {
        let ring = make_ring(7);
        let now = SystemTime::now();
        let now = UNIX_EPOCH + Duration::from_secs(now.duration_since(UNIX_EPOCH).unwrap().as_secs());
        let tok = ring
            .seal_session(&Session {
                email: "Guest@Example.com".into(),
                provider: identity::PROVIDER_GOOGLE.into(),
                issued: now,
                expires: now + Duration::from_secs(12 * 3600),
            })
            .unwrap();
        let got = ring.open_session(&tok, now + Duration::from_secs(3600), Duration::from_secs(12 * 3600)).unwrap();
        assert_eq!(got.email, "guest@example.com");
        assert_eq!(got.provider, identity::PROVIDER_GOOGLE);
        let plain = ring.open(SESSION_COOKIE_NAME, &tok).unwrap();
        let v: serde_json::Value = serde_json::from_str(&plain).unwrap();
        let names: BTreeSet<_> = v.as_object().unwrap().keys().cloned().collect();
        assert_eq!(names.into_iter().collect::<Vec<_>>().join(","), "email,exp,iat,provider");
        let other = make_ring(9);
        assert!(matches!(other.open_session(&tok, now, Duration::from_secs(12 * 3600)), Err(SessionError::Unauthenticated)));
        let mut raw = base64::engine::general_purpose::STANDARD.decode(&tok).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0x40;
        let tampered = base64::engine::general_purpose::STANDARD.encode(raw);
        assert!(matches!(ring.open_session(&tampered, now, Duration::from_secs(12 * 3600)), Err(SessionError::Unauthenticated)));
        let unsigned = base64::engine::general_purpose::STANDARD.encode(br#"{"email":"guest@example.com","provider":"google","iat":1,"exp":9999999999}"#);
        assert!(matches!(ring.open_session(&unsigned, now, Duration::from_secs(12 * 3600)), Err(SessionError::Unauthenticated)));
        assert!(matches!(ring.open_session("", now, Duration::from_secs(12 * 3600)), Err(SessionError::Unauthenticated)));
        let expired = ring
            .seal_session(&Session {
                email: "guest@example.com".into(),
                provider: identity::PROVIDER_GOOGLE.into(),
                issued: now - Duration::from_secs(2 * 3600),
                expires: now - Duration::from_secs(3600),
            })
            .unwrap();
        assert!(matches!(ring.open_session(&expired, now, Duration::from_secs(12 * 3600)), Err(SessionError::Expired)));
        let future = ring
            .seal_session(&Session {
                email: "guest@example.com".into(),
                provider: identity::PROVIDER_GOOGLE.into(),
                issued: now + Duration::from_secs(2 * 3600),
                expires: now + Duration::from_secs(3 * 3600),
            })
            .unwrap();
        assert!(matches!(ring.open_session(&future, now, Duration::from_secs(12 * 3600)), Err(SessionError::Unauthenticated)));
        let long = ring
            .seal_session(&Session {
                email: "guest@example.com".into(),
                provider: identity::PROVIDER_GOOGLE.into(),
                issued: now,
                expires: now + Duration::from_secs(48 * 3600),
            })
            .unwrap();
        assert!(matches!(ring.open_session(&long, now, Duration::from_secs(12 * 3600)), Err(SessionError::Unauthenticated)));
        let oauth = ring
            .seal_oauth(&OAuthState {
                state: "state".into(),
                verifier: "verifier-verifier-verifier-verifier-verifier".into(),
                nonce: "nonce".into(),
                provider: identity::PROVIDER_GOOGLE.into(),
                return_to: "https://notes.example.com/".into(),
                expires: now + Duration::from_secs(600),
            })
            .unwrap();
        assert!(matches!(ring.open_session(&oauth, now, Duration::from_secs(12 * 3600)), Err(SessionError::Unauthenticated)));
        let extra = ring
            .seal(
                SESSION_COOKIE_NAME,
                r#"{"email":"guest@example.com","provider":"google","iat":1,"exp":2,"role":"admin"}"#,
            )
            .unwrap();
        assert!(matches!(
            ring.open_session(&extra, now, Duration::from_secs(12 * 3600)),
            Err(SessionError::Unauthenticated)
        ));
    }

    #[test]
    fn previous_key() {
        let old_key = base64::engine::general_purpose::STANDARD.encode([3u8; 32]);
        let new_key = base64::engine::general_purpose::STANDARD.encode([4u8; 32]);
        let old = KeyRing::new(&old_key, "").unwrap();
        let now = SystemTime::now();
        let now = UNIX_EPOCH + Duration::from_secs(now.duration_since(UNIX_EPOCH).unwrap().as_secs());
        let tok = old
            .seal_session(&Session {
                email: "owner@example.com".into(),
                provider: identity::PROVIDER_GITHUB.into(),
                issued: now,
                expires: now + Duration::from_secs(3600),
            })
            .unwrap();
        let ring = KeyRing::new(&new_key, &old_key).unwrap();
        ring.open_session(&tok, now, Duration::from_secs(3600)).unwrap();
        let fresh = ring
            .seal_session(&Session {
                email: "owner@example.com".into(),
                provider: identity::PROVIDER_GITHUB.into(),
                issued: now,
                expires: now + Duration::from_secs(3600),
            })
            .unwrap();
        assert!(matches!(old.open_session(&fresh, now, Duration::from_secs(3600)), Err(SessionError::Unauthenticated)));
    }

    #[test]
    fn cookie_flags() {
        let c = session_cookie("example.com", "abc", Duration::from_secs(12 * 3600));
        assert_eq!(c.name(), SESSION_COOKIE_NAME);
        assert_eq!(c.domain(), Some("example.com"));
        assert_eq!(c.path(), Some("/"));
        assert_eq!(c.http_only(), Some(true));
        assert_eq!(c.secure(), Some(true));
        assert_eq!(c.same_site(), Some(SameSite::Lax));
        assert_eq!(c.max_age().unwrap().whole_seconds(), 12 * 60 * 60);
        let header = c.to_string();
        for want in ["HttpOnly", "Secure", "SameSite=Lax", "Domain=example.com"] {
            assert!(header.contains(want), "{header}");
        }
        let oauth = oauth_cookie("abc");
        assert!(oauth.domain().is_none());
        assert_eq!(oauth.name(), OAUTH_COOKIE_NAME);
        assert_eq!(oauth.path(), Some("/"));
        assert_eq!(oauth.secure(), Some(true));
        assert_eq!(oauth.http_only(), Some(true));
        let cleared = clear_session_cookie("example.com");
        assert!(cleared.max_age().unwrap().whole_seconds() <= 0);
        assert_eq!(cleared.domain(), Some("example.com"));
        assert_eq!(cleared.secure(), Some(true));
    }
}
