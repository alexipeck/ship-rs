use std::fmt;

use crate::dnsname;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReturnError;

impl fmt::Display for ReturnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("return url not allowed")
    }
}

impl std::error::Error for ReturnError {}

pub fn validate(raw: &str, base: &str) -> Result<String, ReturnError> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 2048 || raw.chars().any(|c| matches!(c, '\r' | '\n' | '\t' | '\\')) {
        return Err(ReturnError);
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains("%0d") || lower.contains("%0a") || lower.contains("%00") || lower.contains("%5c") {
        return Err(ReturnError);
    }
    if !raw.starts_with("https://") {
        return Err(ReturnError);
    }
    let rest = &raw["https://".len()..];
    let host_part = match rest.find(['/', '?', '#']) {
        Some(i) => &rest[..i],
        None => rest,
    };
    if host_part.is_empty() || host_part.contains(['@', '/']) {
        return Err(ReturnError);
    }
    let u = url::Url::parse(raw).map_err(|_| ReturnError)?;
    if u.scheme() != "https" || u.host_str().is_none() || !u.username().is_empty() || u.password().is_some() {
        return Err(ReturnError);
    }
    let host_with_port = match u.port() {
        Some(p) => format!("{}:{p}", u.host_str().unwrap()),
        None => u.host_str().unwrap().to_string(),
    };
    if !dnsname::allowed(&host_with_port, base) {
        return Err(ReturnError);
    }
    let host = dnsname::canonical(u.host_str().unwrap()).map_err(|_| ReturnError)?;
    if !dnsname::allowed(&host, base) {
        return Err(ReturnError);
    }
    let mut rebuilt = url::Url::parse(&format!("https://{host}/")).map_err(|_| ReturnError)?;
    if let Some(port) = u.port() {
        if !(1..=65535).contains(&port) {
            return Err(ReturnError);
        }
        if port != 443 {
            rebuilt.set_port(Some(port)).map_err(|_| ReturnError)?;
        }
    }
    let path = if u.path().is_empty() { "/" } else { u.path() };
    if !path.starts_with('/') || path.starts_with("//") || path.contains('\\') || path.chars().any(|c| c == '\r' || c == '\n') {
        return Err(ReturnError);
    }
    rebuilt.set_path(path);
    if let Some(q) = u.query() {
        rebuilt.set_query(Some(q));
    }
    if let Some(frag) = u.fragment() {
        rebuilt.set_fragment(Some(frag));
    }
    let s = rebuilt.to_string();
    if s.chars().any(|c| matches!(c, '\r' | '\n' | '\\')) || !s.starts_with("https://") {
        return Err(ReturnError);
    }
    let check = url::Url::parse(&s).map_err(|_| ReturnError)?;
    if !check.username().is_empty() || check.password().is_some() {
        return Err(ReturnError);
    }
    let check_host = match check.port() {
        Some(p) => format!("{}:{p}", check.host_str().unwrap_or("")),
        None => check.host_str().unwrap_or("").to_string(),
    };
    if !dnsname::allowed(&check_host, base) {
        return Err(ReturnError);
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_table() {
        let ok = [
            ("https://example.com", "https://example.com/"),
            ("https://example.com/", "https://example.com/"),
            ("https://notes.example.com/path", "https://notes.example.com/path"),
            ("https://notes.example.com/path?x=1&y=2", "https://notes.example.com/path?x=1&y=2"),
            ("https://notes.example.com:18443/path", "https://notes.example.com:18443/path"),
            ("https://notes.example.com:443/path", "https://notes.example.com/path"),
            ("https://auth.example.com/callback/google", "https://auth.example.com/callback/google"),
            ("https://a.b.example.com/", "https://a.b.example.com/"),
            ("https://Notes.Example.com/Path", "https://notes.example.com/Path"),
            ("  https://notes.example.com/docs  ", "https://notes.example.com/docs"),
        ];
        for (input, want) in ok {
            let got = validate(input, "example.com").unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(got, want, "{input}");
        }
        let bad = [
            "",
            "http://notes.example.com/",
            "HTTPS://notes.example.com/",
            "https://evil.com/",
            "https://example.com.evil.com/",
            "https://notexample.com/",
            "//notes.example.com/",
            "https://user:pass@notes.example.com/",
            "https://notes.example.com%00.evil.com/",
            "javascript:alert(1)",
            "https://evil.com#@notes.example.com",
            "https://notes.example.com.evil.com/",
            "/\\notes.example.com",
            "https://notes.example.com\\\n",
            "https:///notes.example.com",
            "https://127.0.0.1/",
            "https://notes.example.com:abc/",
            "https://notes.example.com:-1/",
            "https://.example.com/",
            "https://notes..example.com/",
            "ftp://notes.example.com/",
            "https://notes.example.com/\r\nLocation: https://evil.com",
            "https://auth.example.com.evil.com/",
            "https://example.com%2e.evil.com/",
            "https://notes.example.com%5c.evil.com/",
            "https://user@notes.example.com/",
            " https://evil.com",
        ];
        for raw in bad {
            match validate(raw, "example.com") {
                Ok(got) => panic!("accepted {raw:?} as {got}"),
                Err(_) => {}
            }
        }
    }

    #[test]
    fn fuzz_validate() {
        let seeds = [
            "https://notes.example.com/a",
            "https://evil.com/",
            "//notes.example.com",
            "https://notes.example.com.evil.com/",
            "https://user:pass@notes.example.com/",
        ];
        let mut samples = seeds.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        let mut state = 0x1234_5678_u64;
        for _ in 0..2000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let n = (state % 80) as usize;
            let mut raw = String::new();
            let mut x = state;
            for _ in 0..n {
                x = x.wrapping_mul(1103515245).wrapping_add(12345);
                raw.push(char::from_u32(u32::try_from((x % 96) + 32).unwrap_or(32)).unwrap_or('a'));
            }
            samples.push(raw);
        }
        for raw in samples {
            match validate(&raw, "example.com") {
                Err(_) => {}
                Ok(got) => {
                    let u = url::Url::parse(&got).unwrap();
                    assert_eq!(u.scheme(), "https");
                    assert!(u.username().is_empty());
                    assert!(u.host_str().is_some());
                    assert!(dnsname::allowed(u.host_str().unwrap(), "example.com"), "{got} from {raw}");
                    assert!(!got.chars().any(|c| matches!(c, '\r' | '\n' | '\\')));
                }
            }
        }
    }
}
