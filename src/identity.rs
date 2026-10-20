use crate::dnsname;

pub const PROVIDER_GOOGLE: &str = "google";
pub const PROVIDER_GITHUB: &str = "github";

pub fn valid_provider(p: &str) -> bool {
    p == PROVIDER_GOOGLE || p == PROVIDER_GITHUB
}

pub fn normalize_email(s: &str) -> Result<String, ()> {
    let s = s.trim().to_ascii_lowercase();
    if s.len() < 3 || s.len() > 254 || s.chars().any(|c| c.is_whitespace() || c == '\0') {
        return Err(());
    }
    let Some((local, domain)) = s.split_once('@') else {
        return Err(());
    };
    if local.is_empty() || domain.is_empty() || s.matches('@').count() != 1 {
        return Err(());
    }
    if !valid_local(local) || !dnsname::valid_hostname(domain) {
        return Err(());
    }
    Ok(s)
}

fn valid_local(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 || b[0] == b'.' || b[b.len() - 1] == b'.' || s.contains("..") {
        return false;
    }
    b.iter().all(|c| {
        c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || matches!(*c, b'.' | b'_' | b'%' | b'+' | b'-')
    })
}

pub fn provider_label(provider: &str) -> &'static str {
    match provider {
        PROVIDER_GOOGLE => "Google",
        PROVIDER_GITHUB => "GitHub",
        _ => "the identity provider",
    }
}
