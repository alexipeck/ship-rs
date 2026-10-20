use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicU64;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Private,
    PrivateListed,
}

impl Visibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::PrivateListed => "private-listed",
        }
    }

    pub fn is_public(self) -> bool {
        self == Self::Public
    }

    pub fn badge(self) -> (&'static str, &'static str) {
        match self {
            Self::Public => ("public", "Public"),
            Self::Private => ("protected", "Private"),
            Self::PrivateListed => ("protected", "Sign-in required"),
        }
    }
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
    pub visibility: Visibility,
    pub enabled: bool,
    pub spa: bool,
    pub allow: Vec<String>,
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
    visibility: String,
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
        let visibility = parse_visibility(&self.visibility, self.public, self.unlisted)?;
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
            visibility,
            enabled: self.enabled.unwrap_or(true),
            spa: self.spa.unwrap_or(false),
            allow,
            build: self.build,
        })
    }
}

fn parse_visibility(visibility: &str, public: Option<bool>, unlisted: Option<bool>) -> Result<Visibility, String> {
    let visibility = visibility.trim();
    if !visibility.is_empty() {
        if public.is_some() || unlisted.is_some() {
            return Err("set visibility, or public and unlisted, not both".into());
        }
        return match visibility {
            "public" => Ok(Visibility::Public),
            "private" => Ok(Visibility::Private),
            "private-listed" => Ok(Visibility::PrivateListed),
            _ => Err("visibility must be public, private, or private-listed".into()),
        };
    }
    let public = public.ok_or_else(|| "set visibility, or public".to_string())?;
    let unlisted = unlisted.unwrap_or(false);
    if public && unlisted {
        return Err("a public site cannot be unlisted; set visibility instead".into());
    }
    if public {
        Ok(Visibility::Public)
    } else if unlisted {
        Ok(Visibility::Private)
    } else {
        Ok(Visibility::PrivateListed)
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
        if site.visibility.is_public() {
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
        self.hub_sites(None)
    }

    pub fn hub_sites(&self, email: Option<&str>) -> Vec<Site> {
        let email = email.and_then(|email| identity::normalize_email(email).ok());
        self.sites.iter().filter(|site| site.enabled && self.on_hub(site, email.as_deref())).cloned().collect()
    }

    fn on_hub(&self, site: &Site, email: Option<&str>) -> bool {
        match site.visibility {
            Visibility::Public | Visibility::PrivateListed => true,
            Visibility::Private => match email {
                Some(email) => self.admins.iter().any(|admin| admin == email) || site.allow.iter().any(|allowed| allowed == email),
                None => false,
            },
        }
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
    #[cfg(test)]
    refreshes: AtomicU64,
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
            #[cfg(test)]
            refreshes: AtomicU64::new(0),
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
        // A read emits Access (open, close). refresh() reads the file, so
        // treating Access as a change reloads forever. Create, a data or
        // rename modify, and remove are the events that can change the bytes,
        // including an editor that renames a temp file onto this path.
        let Ok(event) = res else {
            return;
        };
        if watcher_should_refresh(&event, &watch_path) {
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

fn watcher_should_refresh(event: &notify::Event, watch_path: &Path) -> bool {
    if !event_kind_reloads(event.kind) {
        return false;
    }
    event.paths.is_empty() || event.paths.iter().any(|path| path == watch_path)
}

fn event_kind_reloads(kind: notify::EventKind) -> bool {
    match kind {
        notify::EventKind::Create(_) | notify::EventKind::Remove(_) => true,
        notify::EventKind::Modify(notify::event::ModifyKind::Data(_)) => true,
        notify::EventKind::Modify(notify::event::ModifyKind::Name(_)) => true,
        notify::EventKind::Access(_) | notify::EventKind::Any | notify::EventKind::Other => false,
        notify::EventKind::Modify(_) => false,
    }
}

fn refresh(shared: &Shared) {
    #[cfg(test)]
    shared.refreshes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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

[[sites]]
slug = "other"
title = "Other"
deploy = "other"
subdomain = "other"
visibility = "private"
allow = ["someone@example.com"]
"#
    }

    #[test]
    fn parse_and_allow() {
        let (_dir, path) = write_toml(base_toml());
        let cfg = load(&path).unwrap();
        assert_eq!(cfg.admins[0], "owner@example.com");
        let notes = &cfg.sites[1];
        assert_eq!(notes.allow[0], "guest@example.com");
        assert_eq!(notes.visibility, Visibility::PrivateListed);
        assert!(notes.enabled);
        assert_eq!(cfg.sites[3].visibility, Visibility::Private);
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
        let guest = cfg.hub_sites(Some("guest@example.com"));
        assert!(guest.iter().any(|site| site.slug == "hidden"));
        assert!(!guest.iter().any(|site| site.slug == "other"));
        let owner = cfg.hub_sites(Some("owner@example.com"));
        assert!(owner.iter().any(|site| site.slug == "hidden"));
        assert!(owner.iter().any(|site| site.slug == "other"));
        let stranger = cfg.hub_sites(Some("stranger@example.com"));
        assert!(!stranger.iter().any(|site| site.slug == "hidden"));
        assert!(!stranger.iter().any(|site| site.slug == "other"));
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
            ("hidden", base_toml().replacen("public = true", "visibility = \"hidden\"", 1)),
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
    fn reads_do_not_spin_the_watcher() {
        use std::sync::atomic::Ordering;
        use std::thread;
        use std::time::Duration;

        let (dir, path) = write_toml(base_toml());
        let store = Store::open(&path).unwrap();
        let before = store.shared.refreshes.load(Ordering::SeqCst);
        let _ = store.current();
        for _ in 0..40 {
            fs::read(&path).unwrap();
        }
        thread::sleep(Duration::from_millis(300));
        let after_reads = store.shared.refreshes.load(Ordering::SeqCst);
        let reads = after_reads.saturating_sub(before);
        assert!(reads < 5, "reading the config refreshed {reads} times");

        let removed = base_toml().replacen("allow = [\"Guest@Example.com\"]", "allow = []", 1);
        fs::write(&path, removed).unwrap();
        wait_until(Duration::from_secs(2), || {
            let cfg = store.shared.data.lock().unwrap_or_else(|e| e.into_inner()).current.clone();
            cfg.authorize("notes.example.com", "guest@example.com", true).1 == Access::Denied
        });
        thread::sleep(Duration::from_millis(300));
        let after_write = store.shared.refreshes.load(Ordering::SeqCst);
        let writes = after_write.saturating_sub(after_reads);
        assert!(writes > 0, "a write did not refresh");
        assert!(writes < 15, "a write refreshed {writes} times");

        let tmp = dir.path().join("sites.toml.next");
        fs::write(&tmp, base_toml()).unwrap();
        fs::rename(&tmp, &path).unwrap();
        wait_until(Duration::from_secs(2), || {
            let cfg = store.shared.data.lock().unwrap_or_else(|e| e.into_inner()).current.clone();
            cfg.authorize("notes.example.com", "guest@example.com", true).1 == Access::Allowed
        });
    }

    fn wait_until(limit: std::time::Duration, mut ready: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + limit;
        loop {
            if ready() {
                return;
            }
            if std::time::Instant::now() >= deadline {
                panic!("timed out waiting for the config watcher");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn shipped_configs() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for rel in ["examples/sites.toml", "deploy/sites.toml.example", "deploy/sites.arch.toml"] {
            let cfg = load(&root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
            assert_eq!(cfg.base_domain, "example.com");
            assert!(cfg.sites.len() >= 2, "{rel}");
        }
    }
}
