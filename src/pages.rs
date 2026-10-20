pub(crate) fn css() -> &'static str {
    include_str!("ui.css")
}

pub(crate) fn csp_self() -> &'static str {
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
}

pub(crate) fn csp_auth(origin: &str) -> String {
    format!("default-src 'none'; style-src 'unsafe-inline'; form-action {origin}; base-uri 'none'; frame-ancestors 'none'")
}

pub(crate) struct LoginView<'a> {
    pub google: bool,
    pub github: bool,
    pub ret: &'a str,
    pub bad_return: bool,
    pub email: &'a str,
    pub provider: &'a str,
    pub sign_out_return: &'a str,
}

pub(crate) fn login_page(v: &LoginView<'_>) -> String {
    let mut body = String::from("<p class=\"mark\">ship-rs</p>\n<h1>Sign in</h1>\n");
    if v.bad_return {
        body.push_str("<p class=\"fine\">The return address is not allowed.</p>\n");
    }
    if !v.email.is_empty() {
        body.push_str(&format!("<p class=\"who\">Signed in as <strong>{}</strong> via {}.</p>\n", esc(v.email), esc(v.provider)));
    }
    body.push_str("<div class=\"card\">\n<p class=\"lede\">Use the Google or GitHub account whose email is on the list for the site you are opening.</p>\n<div class=\"actions\">\n");
    if v.google {
        body.push_str(&format!("<a class=\"btn\" href=\"/login/google?return={}\">Sign in with Google</a>\n", esc(v.ret)));
    }
    if v.github {
        body.push_str(&format!("<a class=\"btn\" href=\"/login/github?return={}\">Sign in with GitHub</a>\n", esc(v.ret)));
    }
    if !v.google && !v.github {
        body.push_str("<p>Sign-in is not configured on this server.</p>\n");
    }
    if !v.email.is_empty() {
        body.push_str(&format!("<form method=\"post\" action=\"/logout\">\n<input type=\"hidden\" name=\"return\" value=\"{}\">\n<button class=\"secondary\" type=\"submit\">Sign out</button>\n</form>\n", esc(v.sign_out_return)));
    }
    body.push_str("</div>\n</div>\n");
    shell("Sign in", &body)
}

pub(crate) fn sign_in_page(title: &str, url: &str) -> String {
    let body = format!(
        "<p class=\"mark\">ship-rs</p>\n<h1>Sign in required</h1>\n<div class=\"card\">\n<p>{} is only open to invited accounts.</p>\n<p class=\"fine\">You are not signed in.</p>\n<div class=\"actions\">\n<a class=\"btn\" href=\"{}\">Sign in</a>\n</div>\n</div>\n",
        esc(title),
        esc(url)
    );
    shell("Sign in required", &body)
}

pub(crate) struct DenyView<'a> {
    pub title: &'a str,
    pub email: &'a str,
    pub provider: &'a str,
    pub logout_url: &'a str,
    pub sign_out_return: &'a str,
    pub switch_return: &'a str,
}

pub(crate) fn deny_page(v: &DenyView<'_>) -> String {
    let body = format!(
        "<p class=\"mark\">ship-rs</p>\n<h1>Access denied</h1>\n<div class=\"card\">\n<p class=\"who\">Signed in as <strong>{}</strong> via {}.</p>\n<p>That account is not on the allowlist for {}.</p>\n<div class=\"actions\">\n<form method=\"post\" action=\"{}\">\n<input type=\"hidden\" name=\"return\" value=\"{}\">\n<button type=\"submit\">Sign out</button>\n</form>\n<form method=\"post\" action=\"{}\">\n<input type=\"hidden\" name=\"return\" value=\"{}\">\n<button class=\"secondary\" type=\"submit\">Use a different account</button>\n</form>\n</div>\n</div>\n",
        esc(v.email),
        esc(v.provider),
        esc(v.title),
        esc(v.logout_url),
        esc(v.sign_out_return),
        esc(v.logout_url),
        esc(v.switch_return)
    );
    shell("Access denied", &body)
}

pub(crate) fn message_page(title: &str, message: &str) -> String {
    let body = format!("<p class=\"mark\">ship-rs</p>\n<h1>{}</h1>\n<div class=\"card\">\n<p>{}</p>\n</div>\n", esc(title), esc(message));
    shell(title, &body)
}

pub(crate) fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn shell(title: &str, body: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<meta name=\"robots\" content=\"noindex\">\n<title>{}</title>\n<style>{}</style>\n</head>\n<body>\n<main>\n{body}</main>\n</body>\n</html>\n",
        esc(title),
        css()
    )
}
