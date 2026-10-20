use std::fs;
use std::io;
use std::path::Path;

pub fn load(path: &Path) -> io::Result<()> {
    let fi = fs::metadata(path)?;
    if !fi.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} is not a regular file", path.display())));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fi.permissions().mode() & 0o007 != 0 {
            tracing::warn!(path = %path.display(), "env file is world-readable");
        }
    }
    let text = fs::read_to_string(path)?.replace("\r\n", "\n");
    for (i, mut line) in text.split('\n').enumerate() {
        if i == 0 {
            line = line.trim_start_matches('\u{feff}');
        }
        let mut trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("export ") {
            trimmed = rest.trim();
        }
        let Some((key, val)) = trimmed.split_once('=') else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}:{}: expected KEY=VALUE", path.display(), i + 1)));
        };
        let key = key.trim();
        if key.is_empty() || key.chars().any(|c| c == ' ' || c == '\t') {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}:{}: invalid key", path.display(), i + 1)));
        }
        let mut val = val.to_string();
        if val.len() >= 2 {
            let bytes = val.as_bytes();
            if (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"') || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'') {
                val = val[1..val.len() - 1].to_string();
            }
        }
        if std::env::var_os(key).is_some() {
            continue;
        }
        unsafe {
            std::env::set_var(key, &val);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn load_does_not_override() {
        let _g = LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ship-rs.env");
        fs::write(&path, "# comment\nexport KEEP=from-file\nSHIP_RS_COOKIE_KEY=\"abc+def=\"\nHASH=value#not-comment\nQUOTED='two words'\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        unsafe {
            std::env::set_var("KEEP", "from-env");
            std::env::remove_var("SHIP_RS_COOKIE_KEY");
            std::env::remove_var("HASH");
            std::env::remove_var("QUOTED");
        }
        load(&path).unwrap();
        assert_eq!(std::env::var("KEEP").unwrap(), "from-env");
        assert_eq!(std::env::var("SHIP_RS_COOKIE_KEY").unwrap(), "abc+def=");
        assert_eq!(std::env::var("HASH").unwrap(), "value#not-comment");
        assert_eq!(std::env::var("QUOTED").unwrap(), "two words");
        unsafe {
            std::env::remove_var("KEEP");
            std::env::remove_var("SHIP_RS_COOKIE_KEY");
            std::env::remove_var("HASH");
            std::env::remove_var("QUOTED");
        }
    }
}
