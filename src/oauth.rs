use std::sync::Mutex;
use std::time::Duration;

use oauth2::basic::BasicClient;
use oauth2::{AuthType, AuthUrl, TokenResponse as OauthTokenResponse, TokenUrl};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};
use serde::Deserialize;

use crate::identity;

pub const DEFAULT_ISSUER: &str = crate::secrets::DEFAULT_ISSUER;
pub const DEFAULT_GITHUB_AUTH: &str = crate::secrets::DEFAULT_GITHUB_AUTH;
pub const DEFAULT_GITHUB_TOKEN: &str = crate::secrets::DEFAULT_GITHUB_TOKEN;
pub const DEFAULT_GITHUB_EMAIL: &str = crate::secrets::DEFAULT_GITHUB_EMAIL;

#[derive(Debug, thiserror::Error)]
pub enum OauthError {
    #[error("email not verified")]
    EmailUnverified,
    #[error("no primary email")]
    NoPrimaryEmail,
    #[error("{0}")]
    Other(String),
}

pub struct Options {
    pub google_id: String,
    pub google_secret: String,
    pub github_id: String,
    pub github_secret: String,
    pub issuer: String,
    pub github_auth_url: String,
    pub github_token_url: String,
    pub github_emails_url: String,
}

struct Cache {
    key: String,
    meta: CoreProviderMetadata,
}

#[derive(Clone)]
pub struct Client {
    inner: std::sync::Arc<Inner>,
}

struct Inner {
    google_id: String,
    google_secret: String,
    github_id: String,
    github_secret: String,
    issuer: String,
    github_auth: String,
    github_token: String,
    github_emails: String,
    http: reqwest::Client,
    cache: Mutex<Option<Cache>>,
}

impl Client {
    pub fn new(opts: Options) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 {
                    return attempt.error(std::io::Error::other("too many redirects"));
                }
                let Some(orig) = attempt.previous().first().and_then(|u| u.host_str()) else {
                    return attempt.follow();
                };
                match attempt.url().host_str() {
                    Some(host) if host.eq_ignore_ascii_case(orig) => attempt.follow(),
                    _ => attempt.error(std::io::Error::other("redirect left the provider host")),
                }
            }))
            .build()
            .expect("http client");
        Self {
            inner: std::sync::Arc::new(Inner {
                google_id: opts.google_id,
                google_secret: opts.google_secret,
                github_id: opts.github_id,
                github_secret: opts.github_secret,
                issuer: if opts.issuer.is_empty() { DEFAULT_ISSUER.into() } else { opts.issuer },
                github_auth: if opts.github_auth_url.is_empty() { DEFAULT_GITHUB_AUTH.into() } else { opts.github_auth_url },
                github_token: if opts.github_token_url.is_empty() { DEFAULT_GITHUB_TOKEN.into() } else { opts.github_token_url },
                github_emails: if opts.github_emails_url.is_empty() { DEFAULT_GITHUB_EMAIL.into() } else { opts.github_emails_url },
                http,
                cache: Mutex::new(None),
            }),
        }
    }

    pub async fn auth_url(&self, provider: &str, redirect: &str, state: &str, verifier: &str, nonce: &str) -> Result<String, OauthError> {
        match provider {
            identity::PROVIDER_GOOGLE => self.google_auth_url(redirect, state, verifier, nonce).await,
            identity::PROVIDER_GITHUB => self.github_auth_url(redirect, state, verifier),
            _ => Err(OauthError::Other("unknown provider".into())),
        }
    }

    pub async fn complete(&self, provider: &str, redirect: &str, code: &str, verifier: &str, nonce: &str) -> Result<String, OauthError> {
        match provider {
            identity::PROVIDER_GOOGLE => self.complete_google(redirect, code, verifier, nonce).await,
            identity::PROVIDER_GITHUB => self.complete_github(redirect, code, verifier).await,
            _ => Err(OauthError::Other("unknown provider".into())),
        }
    }

    async fn google_meta(&self) -> Result<CoreProviderMetadata, OauthError> {
        let key = format!("{}\n{}", self.inner.issuer, self.inner.google_id);
        if let Some(hit) = self.inner.cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            if hit.key == key {
                return Ok(hit.meta.clone());
            }
        }
        let issuer = IssuerUrl::new(self.inner.issuer.clone()).map_err(|e| OauthError::Other(format!("google issuer: {e}")))?;
        let meta = CoreProviderMetadata::discover_async(issuer, &self.inner.http)
            .await
            .map_err(|e| OauthError::Other(format!("google discovery: {e}")))?;
        let mut guard = self.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(Cache { key, meta: meta.clone() });
        Ok(meta)
    }

    async fn google_auth_url(&self, redirect: &str, state: &str, verifier: &str, nonce: &str) -> Result<String, OauthError> {
        let meta = self.google_meta().await?;
        let redirect_url = RedirectUrl::new(redirect.to_string()).map_err(|e| OauthError::Other(format!("redirect: {e}")))?;
        let client = CoreClient::from_provider_metadata(meta, ClientId::new(self.inner.google_id.clone()), Some(ClientSecret::new(self.inner.google_secret.clone()))).set_redirect_uri(redirect_url);
        let challenge = pkce(verifier)?;
        let redirect_url = RedirectUrl::new(redirect.to_string()).map_err(|e| OauthError::Other(format!("redirect: {e}")))?;
        let state = state.to_string();
        let nonce = nonce.to_string();
        let (url, _, _) = client
            .authorize_url(CoreAuthenticationFlow::AuthorizationCode, move || CsrfToken::new(state), move || Nonce::new(nonce))
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(challenge)
            .set_redirect_uri(std::borrow::Cow::Owned(redirect_url))
            .url();
        Ok(url.to_string())
    }

    async fn complete_google(&self, redirect: &str, code: &str, verifier: &str, nonce: &str) -> Result<String, OauthError> {
        let meta = self.google_meta().await?;
        let redirect_url = RedirectUrl::new(redirect.to_string()).map_err(|e| OauthError::Other(format!("redirect: {e}")))?;
        let client = CoreClient::from_provider_metadata(meta, ClientId::new(self.inner.google_id.clone()), Some(ClientSecret::new(self.inner.google_secret.clone()))).set_redirect_uri(redirect_url);
        let token = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .map_err(|e| OauthError::Other(format!("google token: {e}")))?
            .set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()))
            .request_async(&self.inner.http)
            .await
            .map_err(|_| OauthError::Other("google token exchange failed".into()))?;
        let id_token = token.id_token().ok_or_else(|| OauthError::Other("google token missing id_token".into()))?;
        let claims = id_token
            .claims(&client.id_token_verifier(), &Nonce::new(nonce.to_string()))
            .map_err(|e| OauthError::Other(format!("google id token: {e}")))?;
        if claims.email_verified() != Some(true) {
            return Err(OauthError::EmailUnverified);
        }
        let email = claims.email().ok_or_else(|| OauthError::Other("google token missing email".into()))?;
        identity::normalize_email(&email.to_string()).map_err(|_| OauthError::Other("google email is not usable".into()))
    }

    fn github_client(&self, redirect: &str) -> Result<BasicClient<oauth2::EndpointSet, oauth2::EndpointNotSet, oauth2::EndpointNotSet, oauth2::EndpointNotSet, oauth2::EndpointSet>, OauthError> {
        let auth = AuthUrl::new(self.inner.github_auth.clone()).map_err(|e| OauthError::Other(format!("github auth url: {e}")))?;
        let token = TokenUrl::new(self.inner.github_token.clone()).map_err(|e| OauthError::Other(format!("github token url: {e}")))?;
        let redirect_url = RedirectUrl::new(redirect.to_string()).map_err(|e| OauthError::Other(format!("redirect: {e}")))?;
        Ok(BasicClient::new(ClientId::new(self.inner.github_id.clone()))
            .set_client_secret(ClientSecret::new(self.inner.github_secret.clone()))
            .set_auth_uri(auth)
            .set_token_uri(token)
            .set_redirect_uri(redirect_url)
            .set_auth_type(AuthType::RequestBody))
    }

    fn github_auth_url(&self, redirect: &str, state: &str, verifier: &str) -> Result<String, OauthError> {
        let client = self.github_client(redirect)?;
        let challenge = pkce(verifier)?;
        let (url, _) = client
            .authorize_url(|| CsrfToken::new(state.to_string()))
            .add_scope(Scope::new("user:email".to_string()))
            .set_pkce_challenge(challenge)
            .url();
        Ok(url.to_string())
    }

    async fn complete_github(&self, redirect: &str, code: &str, verifier: &str) -> Result<String, OauthError> {
        let client = self.github_client(redirect)?;
        let token = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()))
            .request_async(&self.inner.http)
            .await
            .map_err(|_| OauthError::Other("github token exchange failed".into()))?;
        let access = token.access_token().secret();
        let res = self
            .inner
            .http
            .get(&self.inner.github_emails)
            .header("Authorization", format!("Bearer {access}"))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "sitegate")
            .send()
            .await
            .map_err(|_| OauthError::Other("github emails request failed".into()))?;
        let status = res.status();
        let body = res.bytes().await.map_err(|_| OauthError::Other("github emails read failed".into()))?;
        if body.len() > 1 << 20 {
            return Err(OauthError::Other("github emails response is too large".into()));
        }
        if status != reqwest::StatusCode::OK {
            return Err(OauthError::Other(format!("github emails: status {}", status.as_u16())));
        }
        let emails: Vec<GhEmail> = serde_json::from_slice(&body).map_err(|_| OauthError::Other("github emails: invalid json".into()))?;
        let mut found = false;
        let mut primary = String::new();
        let mut verified = false;
        for item in emails {
            if !item.primary {
                continue;
            }
            if found {
                return Err(OauthError::Other("github returned more than one primary email".into()));
            }
            found = true;
            primary = item.email;
            verified = item.verified;
        }
        if !found {
            return Err(OauthError::NoPrimaryEmail);
        }
        if !verified {
            return Err(OauthError::EmailUnverified);
        }
        identity::normalize_email(&primary).map_err(|_| OauthError::Other("github email is not usable".into()))
    }
}

#[derive(Deserialize)]
struct GhEmail {
    email: String,
    primary: bool,
    verified: bool,
}

fn pkce(verifier: &str) -> Result<PkceCodeChallenge, OauthError> {
    let verifier = PkceCodeVerifier::new(verifier.to_string());
    if verifier.secret().len() < 43 || verifier.secret().len() > 128 {
        return Err(OauthError::Other("pkce verifier length".into()));
    }
    Ok(PkceCodeChallenge::from_code_verifier_sha256(&verifier))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testidp::{self, Email};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn github_primary_email() {
        let idp = testidp::GitHub::start(
            "gh-id",
            "gh-secret",
            vec![
                Email { email: "other@example.com".into(), primary: false, verified: true },
                Email { email: "Owner@Example.com".into(), primary: true, verified: true },
            ],
        )
        .await;
        let email = github_flow(&idp).await.unwrap();
        assert_eq!(email, "owner@example.com");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn github_rejects_unverified_primary() {
        let idp = testidp::GitHub::start(
            "gh-id",
            "gh-secret",
            vec![
                Email { email: "verified@example.com".into(), primary: false, verified: true },
                Email { email: "primary@example.com".into(), primary: true, verified: false },
            ],
        )
        .await;
        let err = github_flow(&idp).await.unwrap_err();
        assert!(matches!(err, OauthError::EmailUnverified), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn github_rejects_missing_primary() {
        let idp = testidp::GitHub::start(
            "gh-id",
            "gh-secret",
            vec![Email { email: "verified@example.com".into(), primary: false, verified: true }],
        )
        .await;
        let err = github_flow(&idp).await.unwrap_err();
        assert!(matches!(err, OauthError::NoPrimaryEmail), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn google_verified_and_unverified() {
        let idp = testidp::Google::start("g-id", "g-secret", "Owner@Example.com", true).await;
        let email = provider_flow(identity::PROVIDER_GOOGLE, &idp.issuer, "", "", "", &idp.client_id, &idp.client_secret)
            .await
            .unwrap();
        assert_eq!(email, "owner@example.com");
        idp.set_account("Owner@Example.com", false);
        let err = provider_flow(identity::PROVIDER_GOOGLE, &idp.issuer, "", "", "", &idp.client_id, &idp.client_secret)
            .await
            .unwrap_err();
        assert!(matches!(err, OauthError::EmailUnverified), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn google_accepts_string_email_verified() {
        let idp = testidp::Google::start("g-id", "g-secret", "Owner@Example.com", false).await;
        idp.set_verified_as_string("Owner@Example.com", "true");
        let email = provider_flow(identity::PROVIDER_GOOGLE, &idp.issuer, "", "", "", &idp.client_id, &idp.client_secret)
            .await
            .unwrap();
        assert_eq!(email, "owner@example.com");
        idp.set_verified_as_string("Owner@Example.com", "false");
        let err = provider_flow(identity::PROVIDER_GOOGLE, &idp.issuer, "", "", "", &idp.client_id, &idp.client_secret)
            .await
            .unwrap_err();
        assert!(matches!(err, OauthError::EmailUnverified), "{err}");
    }

    async fn github_flow(idp: &testidp::GitHub) -> Result<String, OauthError> {
        provider_flow(identity::PROVIDER_GITHUB, "", &idp.auth_url, &idp.token_url, &idp.emails_url, &idp.client_id, &idp.client_secret).await
    }

    async fn provider_flow(provider: &str, issuer: &str, auth_url: &str, token_url: &str, emails_url: &str, id: &str, secret: &str) -> Result<String, OauthError> {
        let client = Client::new(Options {
            google_id: id.into(),
            google_secret: secret.into(),
            github_id: id.into(),
            github_secret: secret.into(),
            issuer: issuer.into(),
            github_auth_url: auth_url.into(),
            github_token_url: token_url.into(),
            github_emails_url: emails_url.into(),
        });
        let (_challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let verifier = verifier.secret().clone();
        const REDIRECT: &str = "https://auth.example.com/callback/provider";
        let auth = client.auth_url(provider, REDIRECT, "state-fixed", &verifier, "nonce-fixed").await?;
        let res = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
            .get(auth)
            .send()
            .await
            .map_err(|e| OauthError::Other(e.to_string()))?;
        let loc = res
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| OauthError::Other(format!("authorize status {}", res.status())))?
            .to_string();
        let loc = url::Url::parse(&loc).map_err(|e| OauthError::Other(e.to_string()))?;
        let state = loc.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.into_owned()).unwrap_or_default();
        assert_eq!(state, "state-fixed");
        let code = loc.query_pairs().find(|(k, _)| k == "code").map(|(_, v)| v.into_owned()).unwrap_or_default();
        client.complete(provider, REDIRECT, &code, &verifier, "nonce-fixed").await
    }
}
