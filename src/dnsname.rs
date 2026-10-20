use std::net::IpAddr;

pub fn valid_label(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 63 {
        return false;
    }
    for (i, c) in b.iter().enumerate() {
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-';
        if !ok {
            return false;
        }
        if *c == b'-' && (i == 0 || i + 1 == b.len()) {
            return false;
        }
    }
    true
}

pub fn valid_hostname(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 || s.contains("..") {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|label| valid_label(label))
}

pub fn canonical(hostport: &str) -> Result<String, ()> {
    let host = split_host(hostport)?;
    let ascii = idna::domain_to_ascii(&host).map_err(|_| ())?;
    let ascii = ascii.to_ascii_lowercase().trim_end_matches('.').to_string();
    if ascii.starts_with('.') || !valid_hostname(&ascii) || ascii.parse::<IpAddr>().is_ok() {
        return Err(());
    }
    Ok(ascii)
}

pub fn allowed(hostport: &str, base: &str) -> bool {
    let host = match canonical(hostport) {
        Ok(h) => h,
        Err(()) => return false,
    };
    let root = match canonical(base) {
        Ok(h) => h,
        Err(()) => return false,
    };
    host == root || host.ends_with(&format!(".{root}"))
}

fn split_host(hostport: &str) -> Result<String, ()> {
    let hostport = hostport.trim().to_ascii_lowercase();
    if hostport.is_empty() || hostport.chars().any(|c| " \t\r\n\\/@#?".contains(c)) {
        return Err(());
    }
    let (mut host, port) = if let Some((h, p)) = split_host_port(&hostport) {
        (h.to_string(), p.to_string())
    } else if hostport.matches(':').count() == 1 && !hostport.starts_with('[') {
        return Err(());
    } else {
        (hostport, String::new())
    };
    if host.ends_with('.') {
        host.pop();
    }
    if !port.is_empty() {
        let n: u32 = port.parse().map_err(|_| ())?;
        if !(1..=65535).contains(&n) {
            return Err(());
        }
    }
    if host.is_empty() || host.contains(':') {
        return Err(());
    }
    Ok(host)
}

pub(crate) fn split_host_port(addr: &str) -> Option<(&str, &str)> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        if host.is_empty() || port.is_empty() {
            return None;
        }
        return Some((host, port));
    }
    let (host, port) = addr.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() || host.contains(':') {
        return None;
    }
    Some((host, port))
}
