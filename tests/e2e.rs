use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ship::identity;
use ship::session::{self, KeyRing, Session};

const HTTP_PORT: u16 = 19080;
const HTTPS_PORT: u16 = 19443;
const AUTH_PORT: u16 = 19091;

struct Stack {
    caddy: Child,
    gate: Child,
    caddy_log: PathBuf,
    gate_log: PathBuf,
}

impl Drop for Stack {
    fn drop(&mut self) {
        let _ = self.caddy.kill();
        let _ = self.gate.kill();
        let _ = self.caddy.wait();
        let _ = self.gate.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caddy_forward_auth_and_mocked_oauth() {
    let caddy_bin = std::env::var("CADDY_BIN").unwrap_or_else(|_| "/workspace/bin/caddy".into());
    assert!(Path::new(&caddy_bin).is_file(), "caddy binary missing at {caddy_bin}");
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_ship-rs"));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("caddy-data");
    fs::create_dir_all(&data).unwrap();

    let google = ship::testidp::Google::start("e2e-google", "e2e-google-secret", "Guest@Example.com", true).await;
    let github = ship::testidp::GitHub::start(
        "e2e-github",
        "e2e-github-secret",
        vec![
            ship::testidp::Email { email: "other@example.com".into(), primary: false, verified: true },
            ship::testidp::Email { email: "Owner@Example.com".into(), primary: true, verified: true },
        ],
    )
    .await;

    let key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    let cfg_path = dir.path().join("sites.toml");
    write_config(&cfg_path, &root, true);
    let deploy = Command::new(&bin).args(["deploy", "--config"]).arg(&cfg_path).output().unwrap();
    assert!(
        deploy.status.success(),
        "deploy failed\n{}{}",
        String::from_utf8_lossy(&deploy.stdout),
        String::from_utf8_lossy(&deploy.stderr)
    );

    let caddyfile = fs::read_to_string(dir.path().join("Caddyfile")).unwrap();
    let validate = Command::new(&caddy_bin)
        .args(["validate", "--config", dir.path().join("Caddyfile").to_str().unwrap(), "--adapter", "caddyfile"])
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "caddy validate\n{}\n{}\n{}",
        String::from_utf8_lossy(&validate.stdout),
        String::from_utf8_lossy(&validate.stderr),
        caddyfile
    );

    let gate_log = dir.path().join("gate.log");
    let caddy_log = dir.path().join("caddy.log");
    let gate = spawn(
        &bin,
        &["serve", "--config", cfg_path.to_str().unwrap()],
        &[
            ("SHIP_COOKIE_KEY", key.as_str()),
            ("SHIP_GOOGLE_CLIENT_ID", "e2e-google"),
            ("SHIP_GOOGLE_CLIENT_SECRET", "e2e-google-secret"),
            ("SHIP_GITHUB_CLIENT_ID", "e2e-github"),
            ("SHIP_GITHUB_CLIENT_SECRET", "e2e-github-secret"),
            ("SHIP_ALLOW_UNSAFE_OAUTH_OVERRIDES", "1"),
            ("SHIP_OIDC_ISSUER", google.issuer.as_str()),
            ("SHIP_GITHUB_AUTH_URL", github.auth_url.as_str()),
            ("SHIP_GITHUB_TOKEN_URL", github.token_url.as_str()),
            ("SHIP_GITHUB_EMAILS_URL", github.emails_url.as_str()),
            ("SHIP_LISTEN", &format!("127.0.0.1:{AUTH_PORT}")),
        ],
        &gate_log,
    );
    let caddy = spawn(
        Path::new(&caddy_bin),
        &["run", "--config", dir.path().join("Caddyfile").to_str().unwrap(), "--adapter", "caddyfile"],
        &[("XDG_DATA_HOME", data.to_str().unwrap()), ("HOME", dir.path().to_str().unwrap())],
        &caddy_log,
    );
    let stack = Stack { caddy, gate, caddy_log, gate_log };

    wait_health(&stack).await;
    let ca = wait_file(&data.join("caddy/pki/authorities/local/root.crt"), &stack).await;
    let client = https_client(&ca, false, false);
    let authed = https_client(&ca, true, true);

    let (status, public_body) = text_retry(&client, &stack, || client.get(format!("https://hello.example.com:{HTTPS_PORT}/"))).await;
    assert_eq!(status, 200, "{public_body}\n{}", logs(&stack));
    assert!(public_body.contains("Public hello"), "{public_body}");

    let (status, spa_body) = text_retry(&client, &stack, || client.get(format!("https://spa.example.com:{HTTPS_PORT}/tour"))).await;
    assert_eq!(status, 200, "{spa_body}\n{}", logs(&stack));
    assert!(spa_body.contains("SPA demo"), "{spa_body}");

    let (anon_status, anon_headers, anon_body) = send_retry(&stack, || {
        client
            .get(format!("https://notes.example.com:{HTTPS_PORT}/"))
            .header("accept", "text/html")
            .header("sec-fetch-dest", "document")
    })
    .await;
    assert_eq!(anon_status, 401, "{anon_body}\n{}", logs(&stack));
    assert!(anon_headers.get("location").is_none(), "{anon_headers:?}");
    assert!(anon_body.contains("Sign in"), "{anon_body}");
    assert!(anon_body.contains(&format!("https://auth.example.com:{HTTPS_PORT}/?return=")), "{anon_body}");
    assert!(!anon_body.contains("http-equiv") && !anon_body.contains("location.href"));

    let (status, plain_body) = text_retry(&client, &stack, || {
        client.get(format!("https://notes.example.com:{HTTPS_PORT}/docs")).header("accept", "application/json")
    })
    .await;
    assert_eq!(status, 401, "{plain_body}");
    assert_eq!(plain_body, "401 Sign in required\n");

    let ret = format!("https://notes.example.com:{HTTPS_PORT}/");
    let (login_status, login_body) = text_retry(&authed, &stack, || {
        authed.get(format!("https://auth.example.com:{HTTPS_PORT}/login/google?return={}", query_escape(&ret)))
    })
    .await;
    assert_eq!(login_status, 200, "{login_body}\n{}", logs(&stack));
    assert!(login_body.contains("Protected hello"), "{login_body}");

    let gh_client = https_client(&ca, true, true);
    let (gh_status, gh_body) = text_retry(&gh_client, &stack, || {
        gh_client.get(format!("https://auth.example.com:{HTTPS_PORT}/login/github?return={}", query_escape(&ret)))
    })
    .await;
    assert_eq!(gh_status, 200, "{gh_body}\n{}", logs(&stack));
    assert!(gh_body.contains("Protected hello"), "{gh_body}");

    let ring = KeyRing::new(&key, "").unwrap();
    let now = SystemTime::now();
    let now = UNIX_EPOCH + Duration::from_secs(now.duration_since(UNIX_EPOCH).unwrap().as_secs());
    let stranger = seal(&ring, "stranger@example.com", identity::PROVIDER_GOOGLE, now - Duration::from_secs(3600), now + Duration::from_secs(11 * 3600));
    let admin = seal(&ring, "owner@example.com", identity::PROVIDER_GITHUB, now - Duration::from_secs(3600), now + Duration::from_secs(11 * 3600));
    let guest = seal(&ring, "guest@example.com", identity::PROVIDER_GOOGLE, now - Duration::from_secs(3600), now + Duration::from_secs(11 * 3600));
    let expired = seal(&ring, "owner@example.com", identity::PROVIDER_GOOGLE, now - Duration::from_secs(2 * 3600), now - Duration::from_secs(3600));

    let denied = cookie_get(&client, &stack, &stranger).await;
    assert_eq!(denied.0, 403, "{}\n{}", denied.1, logs(&stack));
    assert!(denied.1.contains("stranger@example.com"), "{}", denied.1);
    let allowed = cookie_get(&client, &stack, &admin).await;
    assert_eq!(allowed.0, 200, "{}", allowed.1);
    assert!(allowed.1.contains("Protected hello"), "{}", allowed.1);

    let mut raw = base64::engine::general_purpose::STANDARD.decode(&guest).unwrap();
    let mid = raw.len() / 2;
    raw[mid] ^= 0xff;
    let tampered = base64::engine::general_purpose::STANDARD.encode(raw);
    assert_eq!(cookie_get(&client, &stack, &tampered).await.0, 401);
    assert_eq!(cookie_get(&client, &stack, &expired).await.0, 401);

    let (spoof_status, spoof_body) = text_retry(&client, &stack, || {
        client
            .get(format!("https://notes.example.com:{HTTPS_PORT}/"))
            .header("accept", "text/html")
            .header("x-ship-rs-email", "owner@example.com")
            .header("x-forwarded-host", "evil.example")
    })
    .await;
    assert_eq!(spoof_status, 401, "{spoof_body}\n{}", logs(&stack));

    let (evil_status, evil_body) = text_retry(&client, &stack, || {
        client.get(format!("https://auth.example.com:{HTTPS_PORT}/login/google?return={}", query_escape("https://evil.com/phish")))
    })
    .await;
    assert_eq!(evil_status, 400, "{evil_body}");
    assert!(!evil_body.contains("evil.com"), "{evil_body}");

    let (www_status, www_headers, _) = send_retry(&stack, || {
        client.get(format!("https://www.example.com:{HTTPS_PORT}/hello")).header("accept", "text/html")
    })
    .await;
    assert!(www_status == 301 || www_status == 308, "{www_status} {}", logs(&stack));
    let loc = www_headers.get("location").and_then(|v| v.to_str().ok()).unwrap_or("");
    assert!(loc.starts_with(&format!("https://example.com:{HTTPS_PORT}/")), "{loc}");

    write_config(&cfg_path, &root, false);
    let guest_after = cookie_get(&client, &stack, &guest).await;
    assert_eq!(guest_after.0, 403, "removed email still allowed {}\n{}", guest_after.1, logs(&stack));
    let admin_after = cookie_get(&client, &stack, &admin).await;
    assert_eq!(admin_after.0, 200, "admin lost access {}", admin_after.1);
    fs::write(&cfg_path, "{ not toml").unwrap();
    assert_eq!(cookie_get(&client, &stack, &admin).await.0, 200, "bad config dropped admin\n{}", logs(&stack));
    assert_eq!(cookie_get(&client, &stack, &guest).await.0, 403, "bad config restored guest");

    let (logout_status, logout_headers, logout_body) = send_retry(&stack, || {
        client
            .post(format!("https://auth.example.com:{HTTPS_PORT}/logout"))
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", format!("https://notes.example.com:{HTTPS_PORT}"))
            .body(format!("return={}", query_escape(&ret)))
    })
    .await;
    assert_eq!(logout_status, 303, "{logout_body}\n{}", logs(&stack));
    assert_eq!(logout_headers.get("location").and_then(|v| v.to_str().ok()).unwrap_or(""), ret);
    let set = logout_headers.get("set-cookie").and_then(|v| v.to_str().ok()).unwrap_or("");
    assert!(set.contains("Max-Age=0"), "{set}");
}

fn write_config(path: &Path, root: &Path, allow_guest: bool) {
    let allow = if allow_guest { r#"allow = ["guest@example.com"]"# } else { "allow = []" };
    let dir = path.parent().unwrap();
    let body = format!(
        r#"
base_domain = "example.com"
tls = "internal"
http_port = {http}
https_port = {https}
auth_upstream = "127.0.0.1:{auth}"
caddyfile = "{caddy}"
caddy_admin = "off"
admins = ["owner@example.com"]

[hub]
title = "Example sites"
deploy = "{hub}"

[[sites]]
slug = "hello"
title = "Public hello"
source = "{hello}"
deploy = "{hello_deploy}"
subdomain = "hello"
public = true

[[sites]]
slug = "notes"
title = "Protected hello"
source = "{notes}"
deploy = "{notes_deploy}"
subdomain = "notes"
public = false
{allow}

[[sites]]
slug = "spa"
title = "SPA demo"
source = "{spa}"
deploy = "{spa_deploy}"
subdomain = "spa"
public = true
spa = true
"#,
        http = HTTP_PORT,
        https = HTTPS_PORT,
        auth = AUTH_PORT,
        caddy = dir.join("Caddyfile").display(),
        hub = dir.join("hub").display(),
        hello = root.join("examples/public-hello").display(),
        hello_deploy = dir.join("hello").display(),
        notes = root.join("examples/protected-hello").display(),
        notes_deploy = dir.join("notes").display(),
        spa = root.join("examples/spa-demo").display(),
        spa_deploy = dir.join("spa").display(),
    );
    fs::write(path, body).unwrap();
}

fn spawn(bin: &Path, args: &[&str], env: &[(&str, &str)], log: &Path) -> Child {
    let file = fs::File::create(log).unwrap();
    let err = file.try_clone().unwrap();
    let mut cmd = Command::new(bin);
    cmd.args(args).stdout(Stdio::from(file)).stderr(Stdio::from(err));
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.spawn().unwrap()
}

async fn wait_health(stack: &Stack) {
    let url = format!("http://127.0.0.1:{AUTH_PORT}/healthz");
    for _ in 0..50 {
        if let Ok(res) = reqwest::get(&url).await {
            if res.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("auth service did not start\n{}", logs(stack));
}

async fn wait_file(path: &Path, stack: &Stack) -> Vec<u8> {
    for _ in 0..80 {
        if let Ok(bytes) = fs::read(path) {
            if !bytes.is_empty() {
                return bytes;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("missing {}\n{}", path.display(), logs(stack));
}

fn https_client(ca: &[u8], store: bool, follow: bool) -> reqwest::Client {
    let policy = if follow { reqwest::redirect::Policy::limited(10) } else { reqwest::redirect::Policy::none() };
    let mut b = reqwest::Client::builder().add_root_certificate(reqwest::Certificate::from_pem(ca).unwrap()).redirect(policy);
    for host in ["example.com", "www.example.com", "auth.example.com", "hello.example.com", "notes.example.com", "spa.example.com"] {
        b = b.resolve(host, format!("127.0.0.1:{HTTPS_PORT}").parse().unwrap());
    }
    if store {
        b = b.cookie_provider(Arc::new(reqwest::cookie::Jar::default()));
    }
    b.build().unwrap()
}

async fn send_retry(stack: &Stack, make: impl Fn() -> reqwest::RequestBuilder) -> (u16, reqwest::header::HeaderMap, String) {
    let mut last = String::new();
    for _ in 0..40 {
        match make().send().await {
            Ok(res) => {
                let status = res.status().as_u16();
                let headers = res.headers().clone();
                let body = res.text().await.unwrap_or_default();
                return (status, headers, body);
            }
            Err(err) => last = err.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("request failed: {last}\n{}", logs(stack));
}

async fn text_retry(client: &reqwest::Client, stack: &Stack, make: impl Fn() -> reqwest::RequestBuilder) -> (u16, String) {
    let _ = client;
    let (status, _, body) = send_retry(stack, make).await;
    (status, body)
}

async fn cookie_get(client: &reqwest::Client, stack: &Stack, token: &str) -> (u16, String) {
    let token = token.to_string();
    text_retry(client, stack, || {
        client
            .get(format!("https://notes.example.com:{HTTPS_PORT}/"))
            .header("accept", "text/html")
            .header("sec-fetch-dest", "document")
            .header("cookie", format!("{}={token}", session::SESSION_COOKIE_NAME))
    })
    .await
}

fn seal(ring: &KeyRing, email: &str, provider: &str, issued: SystemTime, expires: SystemTime) -> String {
    ring.seal_session(&Session {
        email: email.into(),
        provider: provider.into(),
        issued,
        expires,
    })
    .unwrap()
}

fn query_escape(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn logs(stack: &Stack) -> String {
    format!(
        "--- gate ---\n{}\n--- caddy ---\n{}",
        fs::read_to_string(&stack.gate_log).unwrap_or_default(),
        fs::read_to_string(&stack.caddy_log).unwrap_or_default()
    )
}
