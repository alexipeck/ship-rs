use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use crate::config::{Config, Site};
use crate::generate;

pub fn deploy(cfg: &Config, reload: bool) -> Result<(), String> {
    for site in &cfg.sites {
        if !site.enabled || site.source.is_none() {
            continue;
        }
        sync_site(site)?;
    }
    generate::write(cfg)?;
    if !reload {
        return Ok(());
    }
    let status = Command::new("systemctl").args(["reload", "caddy"]).status().map_err(|e| format!("reload caddy: {e}"))?;
    if !status.success() {
        return Err(format!("reload caddy: exit {}", status.code().unwrap_or(-1)));
    }
    Ok(())
}

fn sync_site(site: &Site) -> Result<(), String> {
    let source = site.source.as_ref().ok_or_else(|| format!("site {} source is missing", site.slug))?;
    let st = fs::metadata(source).map_err(|e| format!("site {} source: {e}", site.slug))?;
    if !st.is_dir() {
        return Err(format!("site {} source is not a directory", site.slug));
    }
    if !site.build.is_empty() {
        let status = Command::new("sh")
            .arg("-c")
            .arg(&site.build)
            .current_dir(source)
            .status()
            .map_err(|e| format!("build {}: {e}", site.slug))?;
        if !status.success() {
            return Err(format!("build {}: exit {}", site.slug, status.code().unwrap_or(-1)));
        }
    }
    fs::create_dir_all(&site.deploy).map_err(|e| e.to_string())?;
    let status = Command::new("rsync")
        .args(["-a", "--delete", "--safe-links", &with_slash(source), &with_slash(&site.deploy)])
        .status()
        .map_err(|e| format!("rsync {}: {e}", site.slug))?;
    if !status.success() {
        return Err(format!("rsync {}: exit {}", site.slug, status.code().unwrap_or(-1)));
    }
    make_readable(&site.deploy)
}

fn with_slash(path: &Path) -> String {
    let mut s = path.display().to_string();
    if !s.ends_with('/') {
        s.push('/');
    }
    s
}

fn make_readable(root: &Path) -> Result<(), String> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
            for ent in fs::read_dir(&path).map_err(|e| e.to_string())? {
                let ent = ent.map_err(|e| e.to_string())?;
                stack.push(ent.path());
            }
        } else if meta.is_file() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn sync_and_generate() {
        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("index.html"), "hello-page").unwrap();
        fs::set_permissions(src.join("index.html"), fs::Permissions::from_mode(0o600)).unwrap();
        let dest = root.path().join("dest");
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("old.txt"), "stale").unwrap();
        let body = r#"
base_domain = "example.com"
tls = "internal"
auth_upstream = "127.0.0.1:8091"
caddyfile = "Caddyfile"
admins = ["owner@example.com"]

[hub]
title = "Example sites"
deploy = "hub"

[[sites]]
slug = "hello"
title = "Public hello"
source = "src"
deploy = "dest"
subdomain = "hello"
public = true
build = "printf built > built.txt"
"#;
        let path = root.path().join("sites.toml");
        fs::write(&path, body).unwrap();
        let cfg = config::load(&path).unwrap();
        deploy(&cfg, false).unwrap();
        let got = fs::read(cfg.sites[0].deploy.join("index.html")).unwrap();
        assert_eq!(got, b"hello-page");
        assert!(!cfg.sites[0].deploy.join("old.txt").exists());
        let built = fs::read_to_string(cfg.sites[0].source.as_ref().unwrap().join("built.txt")).unwrap();
        assert_eq!(built, "built");
        let mode = fs::metadata(cfg.sites[0].deploy.join("index.html")).unwrap().permissions().mode();
        assert_ne!(mode & 0o044, 0);
        let caddy = fs::read_to_string(&cfg.caddyfile).unwrap();
        assert!(caddy.contains("hello.example.com"), "{caddy}");
        let hub = fs::read_to_string(cfg.hub.deploy.join("index.html")).unwrap();
        assert!(hub.contains("Public hello"), "{hub}");
    }
}
