use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use notify::Watcher;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::dnsname::{self, split_host_port};
use crate::identity;

pub const DEFAULT_AUTH_UPSTREAM: &str = "127.0.0.1:8091";
pub const TLS_AUTO: &str = "auto";
pub const TLS_INTERNAL: &str = "internal";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Unknown,
    Disabled,
    Public,
    Anonymous,
    Denied,
    Allowed,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub path: PathBuf,
    pub base_domain: String,
    pub acme_email: String,
    pub tls: String,
    pub http_port: u16,
    pub https_port: u16,
    pub auth_upstream: String,
    pub caddyfile: PathBuf,
    pub caddy_admin: String,
    pub preview_addr: String,
    pub admins: Vec<String>,
    pub hub: Hub,
    pub sites: Vec<Site>,
}

#[derive(Clone, Debug)]
pub struct Hub {
    pub title: String,
    pub deploy: PathBuf,
}

#[derive(Clone, Debug)]
pub struct Site {
    pub slug: String,
    pub title: String,
    pub source: Option<PathBuf>,
    pub deploy: PathBuf,
    pub subdomain: String,
    pub fqdn: String,
    pub public: bool,
    pub enabled: bool,
    pub spa: bool,
    pub allow: Vec<String>,
    pub unlisted: bool,
    pub build: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    base_domain: String,
    #[serde(default)]
    acme_email: String,
    #[serde(default)]
    tls: String,
    #[serde(default)]
    http_port: Option<i64>,
    #[serde(default)]
    https_port: Option<i64>,
    #[serde(default)]
    auth_upstream: String,
    #[serde(default)]
    caddyfile: String,
    #[serde(default)]
    caddy_admin: String,
    #[serde(default)]
    preview_addr: String,
    #[serde(default)]
    admins: Vec<String>,
    #[serde(default)]
    hub: FileHub,
    #[serde(default)]
    sites: Vec<FileSite>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileHub {
    #[serde(default)]
    title: String,
    #[serde(default)]
    deploy: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSite {
    slug: String,
    title: String,
    #[serde(default)]
    source: String,
    deploy: String,
    subdomain: String,
    #[serde(default)]
    public: Option<bool>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    spa: Option<bool>,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    unlisted: Option<bool>,
    #[serde(default)]
    build: String,
}

pub fn load(path: &Path) -> Result<Config, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    parse(&bytes, path)
}

pub fn parse(bytes: &[u8], path: &Path) -> Result<Config, String> {
    let abs = abs_path(path).map_err(|e| e.to_string())?;
    let text = std::str::from_utf8(bytes).map_err(|e| format!("parse {}: {e}", abs.display()))?;
    let raw: FileConfig = toml::from_str(text).map_err(|e| format!("parse {}: {e}", abs.display()))?;
    let mut cfg = raw.into_config(abs.parent().unwrap_or_else(|| Path::new("/"))).map_err(|e| format!("parse {}: {e}", abs.display()))?;
    cfg.path = abs;
    Ok(cfg)
}

impl FileConfig {
    fn into_config(self, base_dir: &Path) -> Result<Config, String> {
        let domain = self.base_domain.trim().to_ascii_lowercase();
        if !dnsname::valid_hostname(&domain) {
            return Err("base_domain must be a hostname like example.com".into());
        }
        let tls = if self.tls.is_empty() { TLS_AUTO.to_string() } else { self.tls };
        if tls != TLS_AUTO && tls != TLS_INTERNAL {
            return Err(format!("tls must be {TLS_AUTO:?} or {TLS_INTERNAL:?}"));
        }
        let http_port = port_or(self.http_port, 80)?;
        let https_port = port_or(self.https_port, 443)?;
        if http_port == https_port {
            return Err("http_port and https_port must be different ports".into());
        }
        let upstream = if self.auth_upstream.is_empty() {
            DEFAULT_AUTH_UPSTREAM.to_string()
        } else {
            self.auth_upstream
        };
        loopback_addr(&upstream).map_err(|e| format!("auth_upstream: {e}"))?;
        if !self.caddy_admin.is_empty() && self.caddy_admin != "off" {
            loopback_addr(&self.caddy_admin).map_err(|e| format!("caddy_admin: {e}"))?;
        }
        if !self.preview_addr.is_empty() {
            loopback_addr(&self.preview_addr).map_err(|e| format!("preview_addr: {e}"))?;
        }
        let acme = if self.acme_email.is_empty() {
            String::new()
        } else {
            identity::normalize_email(&self.acme_email).map_err(|_| format!("acme_email: invalid email"))?
        };
        let admins = normalize_emails("admin", &self.admins)?;
        if self.hub.deploy.trim().is_empty() {
            return Err("hub.deploy is required".into());
        }
        let hub_deploy = resolve_path(base_dir, &self.hub.deploy).map_err(|e| format!("hub.deploy: {e}"))?;
        let mut title = self.hub.title.trim().to_string();
        if title.is_empty() {
            title = "Sites".into();
        }
        valid_title(&title).map_err(|e| format!("hub.title: {e}"))?;
        let caddyfile = if self.caddyfile.is_empty() {
            PathBuf::new()
        } else {
            resolve_path(base_dir, &self.caddyfile).map_err(|e| format!("caddyfile: {e}"))?
        };
        let mut cfg = Config {
            path: PathBuf::new(),
            base_domain: domain.clone(),
            acme_email: acme,
            tls,
            http_port,
            https_port,
            auth_upstream: upstream,
            caddyfile,
            caddy_admin: self.caddy_admin,
            preview_addr: self.preview_addr,
            admins,
            hub: Hub { title, deploy: hub_deploy.clone() },
            sites: Vec::new(),
        };
        let mut seen_slug = HashSet::new();
        let mut seen_host = HashSet::new();
        let mut seen_deploy = HashSet::new();
        seen_deploy.insert(hub_deploy);
        for (i, raw_site) in self.sites.into_iter().enumerate() {
            let site = raw_site.into_site(base_dir, &domain).map_err(|e| format!("sites[{i}]: {e}"))?;
            if !seen_slug.insert(site.slug.clone()) {
                return Err(format!("duplicate slug {:?}", site.slug));
            }
            if !seen_host.insert(site.fqdn.clone()) {
                return Err(format!("duplicate subdomain {:?}", site.subdomain));
            }
            if !seen_deploy.insert(site.deploy.clone()) {
                return Err(format!("deploy path {} is used more than once", site.deploy.display()));
            }
            cfg.sites.push(site);
        }
        Ok(cfg)
    }
}

impl FileSite {
    fn into_site(self, base_dir: &Path, domain: &str) -> Result<Site, String> {
        let slug = self.slug.trim().to_ascii_lowercase();
        let sub = self.subdomain.trim().to_ascii_lowercase();
        if !dnsname::valid_label(&slug) {
            return Err("slug must be a single dns label".into());
        }
        if !dnsname::valid_label(&sub) {
            return Err("subdomain must be a single dns label".into());
        }
        if sub == "auth" || sub == "www" {
            return Err(format!("subdomain {sub:?} is reserved"));
        }
        let public = self.public.ok_or_else(|| "public must be set".to_string())?;
        let title = self.title.trim().to_string();
        valid_title(&title)?;
        if self.deploy.trim().is_empty() {
            return Err("deploy is required".into());
        }
        let deploy = resolve_path(base_dir, &self.deploy).map_err(|e| format!("deploy: {e}"))?;
        let source = if self.source.trim().is_empty() {
            None
        } else {
            Some(resolve_path(base_dir, &self.source).map_err(|e| format!("source: {e}"))?)
        };
        if self.build.chars().any(|c| c == '\r' || c == '\n' || c == '\0') || self.build.len() > 2000 {
            return Err("build command must not contain newlines and must be at most 2000 characters".into());
        }
        let allow = normalize_emails("allow", &self.allow)?;
        Ok(Site {
            slug,
            title,
            source,
            deploy,
            subdomain: sub.clone(),
            fqdn: format!("{sub}.{domain}"),
            public,
            enabled: self.enabled.unwrap_or(true),
            spa: self.spa.unwrap_or(false),
            allow,
            unlisted: self.unlisted.unwrap_or(false),
            build: self.build,
        })
    }
}

impl Config {
    pub fn authorize(&self, hostport: &str, email: &str, signed_in: bool) -> (Option<Site>, Access) {
        let host = match dnsname::canonical(hostport) {
            Ok(h) => h,
            Err(()) => return (None, Access::Unknown),
        };
        let Some(site) = self.sites.iter().find(|s| s.fqdn == host).cloned() else {
            return (None, Access::Unknown);
        };
        if !site.enabled {
            return (Some(site), Access::Disabled);
        }
        if site.public {
            return (Some(site), Access::Public);
        }
        if !signed_in || email.is_empty() {
            return (Some(site), Access::Anonymous);
        }
        let Ok(norm) = identity::normalize_email(email) else {
            return (Some(site), Access::Denied);
        };
        if self.admins.iter().any(|a| a == &norm) || site.allow.iter().any(|a| a == &norm) {
            return (Some(site), Access::Allowed);
        }
        (Some(site), Access::Denied)
    }

    pub fn listed(&self) -> Vec<Site> {
        self.sites.iter().filter(|s| s.enabled && !s.unlisted).cloned().collect()
    }

    pub fn origin(&self, host: &str) -> String {
        if self.https_port == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{}", self.https_port)
        }
    }

    pub fn auth_origin(&self) -> String {
        self.origin(&format!("auth.{}", self.base_domain))
    }

    pub fn hub_origin(&self) -> String {
        format!("{}/", self.origin(&self.base_domain))
    }

    pub fn site_origin(&self, site: &Site) -> String {
        format!("{}/", self.origin(&site.fqdn))
    }

    pub fn display_host(&self, host: &str) -> String {
        if self.https_port == 443 {
            host.to_string()
        } else {
            format!("{host}:{}", self.https_port)
        }
    }
}

struct Data {
    path: PathBuf,
    current: Config,
    good_sum: [u8; 32],
    bad_sum: Option<[u8; 32]>,
    read_err: Option<String>,
}

struct Shared {
    data: Mutex<Data>,
    watcher: Mutex<Option<notify::RecommendedWatcher>>,
}

#[derive(Clone)]
pub struct Store {
    shared: Arc<Shared>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        let abs = abs_path(path).map_err(|e| e.to_string())?;
        let bytes = fs::read(&abs).map_err(|e| e.to_string())?;
        let cfg = parse(&bytes, &abs)?;
        let shared = Arc::new(Shared {
            data: Mutex::new(Data {
                path: cfg.path.clone(),
                current: cfg,
                good_sum: sha256(&bytes),
                bad_sum: None,
                read_err: None,
            }),
            watcher: Mutex::new(None),
        });
        start_watch(&shared);
        Ok(Store { shared })
    }

    pub fn current(&self) -> Config {
        refresh(&self.shared);
        self.shared.data.lock().unwrap_or_else(|e| e.into_inner()).current.clone()
    }

    pub fn path(&self) -> PathBuf {
        self.shared.data.lock().unwrap_or_else(|e| e.into_inner()).path.clone()
    }
}

fn start_watch(shared: &Arc<Shared>) {
    let path = shared.data.lock().unwrap_or_else(|e| e.into_inner()).path.clone();
    let Some(parent) = path.parent().map(|p| p.to_path_buf()) else {
        return;
    };
    let shared2 = Arc::clone(shared);
    let watch_path = path.clone();
    let watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
        let relevant = match res {
            Ok(event) => event.paths.is_empty() || event.paths.iter().any(|p| p == &watch_path),
            Err(_) => true,
        };
        if relevant {
            refresh(&shared2);
        }
    });
    match watcher {
        Ok(mut watcher) => {
            if let Err(err) = watcher.watch(&parent, notify::RecursiveMode::NonRecursive) {
                tracing::warn!(path = %path.display(), error = %err, "config watch failed; requests still reload the file");
                return;
            }
            *shared.watcher.lock().unwrap_or_else(|e| e.into_inner()) = Some(watcher);
        }
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "config watch failed; requests still reload the file");
        }
    }
}

fn refresh(shared: &Shared) {
    let mut data = shared.data.lock().unwrap_or_else(|e| e.into_inner());
    let bytes = match fs::read(&data.path) {
        Ok(b) => b,
        Err(err) => {
            let msg = err.to_string();
            if data.read_err.as_deref() != Some(msg.as_str()) {
                tracing::warn!(path = %data.path.display(), error = %err, "config read failed; keeping last good config");
                data.read_err = Some(msg);
            }
            return;
        }
    };
    data.read_err = None;
    let sum = sha256(&bytes);
    if sum == data.good_sum {
        return;
    }
    match parse(&bytes, &data.path) {
        Ok(cfg) => {
            let n = cfg.sites.len();
            let path = cfg.path.clone();
            data.current = cfg;
            data.good_sum = sum;
            data.bad_sum = None;
            tracing::info!(path = %path.display(), sites = n, "reloaded config");
        }
        Err(err) => {
            if data.bad_sum != Some(sum) {
                tracing::warn!(path = %data.path.display(), error = %err, "config reload failed; keeping last good config");
                data.bad_sum = Some(sum);
            }
        }
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

fn port_or(raw: Option<i64>, default: u16) -> Result<u16, String> {
    let n = raw.unwrap_or(i64::from(default));
    if !(1..=65535).contains(&n) {
        return Err("http_port and https_port must be different ports".into());
    }
    Ok(n as u16)
}

fn normalize_emails(kind: &str, input: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in input {
        let email = identity::normalize_email(raw).map_err(|_| format!("{kind} email {:?} is invalid", raw.trim()))?;
        if seen.insert(email.clone()) {
            out.push(email);
        }
    }
    Ok(out)
}

fn valid_title(title: &str) -> Result<(), String> {
    if title.is_empty() || title.len() > 80 || title.chars().any(|c| matches!(c, '\r' | '\n' | '\0' | '<' | '>')) {
        return Err("title must be 1-80 characters without newlines or html".into());
    }
    Ok(())
}

fn resolve_path(base_dir: &Path, p: &str) -> Result<PathBuf, String> {
    let p = p.trim();
    if p.is_empty() || p.chars().any(|c| "\r\n\u{0} #{}\"'`;$&|<>\\".contains(c)) {
        return Err(format!("path {p:?} contains characters that are not allowed"));
    }
    let path = Path::new(p);
    let joined = if path.is_absolute() { path.to_path_buf() } else { base_dir.join(path) };
    let abs = clean_path(&joined);
    if abs == Path::new("/") {
        return Err("refusing filesystem root".into());
    }
    Ok(abs)
}

pub fn abs_path(path: &Path) -> std::io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(clean_path(path))
    } else {
        Ok(clean_path(&std::env::current_dir()?.join(path)))
    }
}

fn clean_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(s) => out.push(s),
            Component::Prefix(_) => {}
        }
    }
    if out.as_os_str().is_empty() {
        out.push("/");
    }
    out
}

fn loopback_addr(addr: &str) -> Result<(), String> {
    let Some((host, port)) = split_host_port(addr) else {
        return Err(format!("{addr:?} is not host:port"));
    };
    let n: u32 = port.parse().map_err(|_| format!("bad port in {addr:?}"))?;
    if !(1..=65535).contains(&n) {
        return Err(format!("bad port in {addr:?}"));
    }
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(());
    }
    let ip: IpAddr = host.parse().map_err(|_| format!("{host} is not a loopback address"))?;
    if !ip.is_loopback() {
        return Err(format!("{host} is not a loopback address"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_toml(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sites.toml");
        fs::write(&path, body).unwrap();
        (dir, path)
    }

    fn base_toml() -> &'static str {
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

[[sites]]
slug = "old"
title = "Old"
deploy = "old"
subdomain = "old"
public = false
enabled = false
allow = ["guest@example.com"]

[[sites]]
slug = "hidden"
title = "Hidden"
deploy = "hidden"
subdomain = "hidden"
public = false
unlisted = true
allow = ["guest@example.com"]
"#
    }

    #[test]
    fn parse_and_allow() {
        let (_dir, path) = write_toml(base_toml());
        let cfg = load(&path).unwrap();
        assert_eq!(cfg.admins[0], "owner@example.com");
        let notes = &cfg.sites[1];
        assert_eq!(notes.allow[0], "guest@example.com");
        assert!(!notes.public);
        assert!(notes.enabled);
        assert_eq!(cfg.authorize("notes.example.com", "guest@example.com", true).1, Access::Allowed);
        assert_eq!(cfg.authorize("notes.example.com", "GUEST@example.com", true).1, Access::Allowed);
        assert_eq!(cfg.authorize("notes.example.com", "owner@example.com", true).1, Access::Allowed);
        assert_eq!(cfg.authorize("NOTES.example.com", "Owner@Example.com", true).1, Access::Allowed);
        assert_eq!(cfg.authorize("notes.example.com", "stranger@example.com", true).1, Access::Denied);
        assert_eq!(cfg.authorize("notes.example.com", "", false).1, Access::Anonymous);
        assert_eq!(cfg.authorize("hello.example.com", "", false).1, Access::Public);
        assert_eq!(cfg.authorize("old.example.com", "guest@example.com", true).1, Access::Disabled);
        assert_eq!(cfg.authorize("missing.example.com", "owner@example.com", true).1, Access::Unknown);
        assert_eq!(cfg.authorize("notes.example.com:18443", "guest@example.com", true).1, Access::Allowed);
        let listed = cfg.listed();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].slug, "hello");
        assert_eq!(listed[1].slug, "notes");
        assert!(cfg.hub.deploy.starts_with("/"));
    }

    #[test]
    fn rejects_bad_config() {
        let cases = [
            ("secret", format!("google_client_secret = \"x\"\n{}", base_toml())),
            ("public", base_toml().replacen("public = true\n", "", 1)),
            ("reserved", base_toml().replacen("subdomain = \"hello\"", "subdomain = \"auth\"", 1)),
            ("dup", format!("{}\n[[sites]]\nslug = \"hello\"\ntitle = \"Again\"\ndeploy = \"again\"\nsubdomain = \"hello2\"\npublic = true\n", base_toml())),
            ("upstream", base_toml().replacen("auth_upstream = \"127.0.0.1:8091\"", "auth_upstream = \"0.0.0.0:8091\"", 1)),
            ("email", base_toml().replacen("admins = [\"Owner@Example.com\"]", "admins = [\"not-an-email\"]", 1)),
        ];
        for (name, body) in cases {
            let (_dir, path) = write_toml(&body);
            assert!(load(&path).is_err(), "{name}");
        }
    }

    #[test]
    fn reload_keeps_last_good() {
        let (_dir, path) = write_toml(base_toml());
        let store = Store::open(&path).unwrap();
        assert_eq!(store.current().authorize("notes.example.com", "guest@example.com", true).1, Access::Allowed);
        let removed = base_toml().replacen("allow = [\"Guest@Example.com\"]", "allow = []", 1);
        fs::write(&path, removed).unwrap();
        let cfg = store.current();
        assert_eq!(cfg.authorize("notes.example.com", "guest@example.com", true).1, Access::Denied);
        assert_eq!(cfg.authorize("notes.example.com", "owner@example.com", true).1, Access::Allowed);
        fs::write(&path, "this is not toml [[[").unwrap();
        let cfg = store.current();
        assert_eq!(cfg.authorize("notes.example.com", "owner@example.com", true).1, Access::Allowed);
        assert_eq!(cfg.authorize("notes.example.com", "guest@example.com", true).1, Access::Denied);
        fs::remove_file(&path).unwrap();
        assert_eq!(store.current().authorize("notes.example.com", "owner@example.com", true).1, Access::Allowed);
    }

    #[test]
    fn shipped_configs() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for rel in ["examples/sites.toml", "deploy/sites.toml.example"] {
            let cfg = load(&root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
            assert_eq!(cfg.base_domain, "example.com");
            assert!(cfg.sites.len() >= 2, "{rel}");
        }
    }
}
