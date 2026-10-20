use crate::theme::Appearance;

pub(crate) fn css(look: &Appearance) -> String {
    let mut out = String::from(include_str!("ui.css"));
    out.push_str(&look.accent_css());
    out
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

pub(crate) fn login_page(v: &LoginView<'_>, look: &Appearance) -> String {
    let _ = v.provider;
    let mut body = String::from("<h1>Sign in</h1>\n");
    if v.bad_return {
        body.push_str("<p class=\"status\" role=\"alert\">Invalid link</p>\n");
    }
    body.push_str("<div class=\"stack\">\n");
    if v.google {
        body.push_str(&format!(
            "<a class=\"btn brand google\" href=\"/login/google?return={}\">{}<span>Sign in with Google</span></a>\n",
            esc(v.ret),
            google_mark()
        ));
    }
    if v.github {
        body.push_str(&format!(
            "<a class=\"btn brand github\" href=\"/login/github?return={}\">{}<span>Sign in with GitHub</span></a>\n",
            esc(v.ret),
            github_mark()
        ));
    }
    if !v.google && !v.github {
        body.push_str("<p class=\"status\">Unavailable</p>\n");
    }
    body.push_str("</div>\n");
    if !v.email.is_empty() {
        body.push_str(&format!(
            "<p class=\"who\">{}</p>\n<form method=\"post\" action=\"/logout\">\n<input type=\"hidden\" name=\"return\" value=\"{}\">\n<button class=\"secondary\" type=\"submit\">Sign out</button>\n</form>\n",
            esc(v.email),
            esc(v.sign_out_return)
        ));
    }
    document("Sign in", &body, look, true, true)
}

pub(crate) fn sign_in_page(url: &str, look: &Appearance) -> String {
    let body = format!(
        "<h1>Sign-in required</h1>\n<div class=\"actions\">\n<a class=\"btn\" href=\"{}\">Sign in</a>\n</div>\n",
        esc(url)
    );
    document("Sign-in required", &body, look, true, true)
}

pub(crate) struct DenyView<'a> {
    pub title: &'a str,
    pub email: &'a str,
    pub provider: &'a str,
    pub logout_url: &'a str,
    pub sign_out_return: &'a str,
    pub switch_return: &'a str,
}

pub(crate) fn deny_page(v: &DenyView<'_>, look: &Appearance) -> String {
    let _ = (v.title, v.provider);
    let body = format!(
        "<h1>Access denied</h1>\n<p class=\"who\">{}</p>\n<div class=\"actions\">\n<form method=\"post\" action=\"{}\">\n<input type=\"hidden\" name=\"return\" value=\"{}\">\n<button type=\"submit\">Sign out</button>\n</form>\n<form method=\"post\" action=\"{}\">\n<input type=\"hidden\" name=\"return\" value=\"{}\">\n<button class=\"secondary\" type=\"submit\">Use a different account</button>\n</form>\n</div>\n",
        esc(v.email),
        esc(v.logout_url),
        esc(v.sign_out_return),
        esc(v.logout_url),
        esc(v.switch_return)
    );
    document("Access denied", &body, look, true, true)
}

pub(crate) fn message_page(title: &str, detail: &str, look: &Appearance) -> String {
    let mut body = format!("<h1>{}</h1>\n", esc(title));
    if !detail.is_empty() {
        body.push_str(&format!("<p class=\"ref\">{}</p>\n", esc(detail)));
    }
    document(title, &body, look, true, true)
}

pub(crate) fn document(title: &str, body: &str, look: &Appearance, gate: bool, noindex: bool) -> String {
    let robots = if noindex { "<meta name=\"robots\" content=\"noindex\">\n" } else { "" };
    let class = if gate { " class=\"gate\"" } else { "" };
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\" class=\"{}\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<meta name=\"color-scheme\" content=\"{}\">\n{robots}<title>{}</title>\n<style>{}</style>\n</head>\n<body>\n<main{class}>\n{body}</main>\n</body>\n</html>\n",
        look.classes(),
        look.color_scheme(),
        esc(title),
        css(look),
    )
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

fn google_mark() -> &'static str {
    "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 48 48\" aria-hidden=\"true\"><path fill=\"#FFC107\" d=\"M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 12.955 4 4 12.955 4 24s8.955 20 20 20 20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z\"/><path fill=\"#FF3D00\" d=\"M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 16.318 4 9.656 8.337 6.306 14.691z\"/><path fill=\"#4CAF50\" d=\"M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238C29.211 35.091 26.715 36 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z\"/><path fill=\"#1976D2\" d=\"M43.611 20.083H42V20H24v8h11.303c-.792 2.237-2.231 4.166-4.087 5.571.001-.001.002-.001.003-.002l6.19 5.238C36.971 39.205 44 34 44 24c0-1.341-.138-2.65-.389-3.917z\"/></svg>"
}

fn github_mark() -> &'static str {
    "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 16 16\" aria-hidden=\"true\" fill=\"currentColor\"><path d=\"M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z\"/></svg>"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::{Appearance, ColorMode, Preset, Rgb};

    #[test]
    fn visitor_copy_has_no_brand_or_explanation() {
        let look = Appearance::default();
        let login = login_page(
            &LoginView {
                google: true,
                github: true,
                ret: "",
                bad_return: false,
                email: "",
                provider: "",
                sign_out_return: "https://example.com/",
            },
            &look,
        );
        assert!(login.contains("Sign in with Google"), "{login}");
        assert!(login.contains("Sign in with GitHub"), "{login}");
        assert!(login.contains("<svg"), "{login}");
        assert!(login.contains("aria-hidden=\"true\""));
        assert!(!login.to_ascii_lowercase().contains("ship-rs"));
        assert!(!login.contains("on the list"));
        assert!(!login.contains("you can sign in"));
        assert!(login.contains("prefers-color-scheme"));
        assert!(login.contains("mode-auto"));

        let required = sign_in_page("https://auth.example.com/", &look);
        assert!(required.contains("<h1>Sign-in required</h1>"));
        assert!(required.contains(">Sign in</a>"));
        assert!(!required.contains("invited"));
        assert!(!required.contains("not signed in"));

        let denied = deny_page(
            &DenyView {
                title: "Notes",
                email: "guest@example.com",
                provider: "Google",
                logout_url: "https://auth.example.com/logout",
                sign_out_return: "https://notes.example.com/",
                switch_return: "https://auth.example.com/?return=1",
            },
            &look,
        );
        assert!(denied.contains("<h1>Access denied</h1>"));
        assert!(denied.contains("guest@example.com"));
        assert!(!denied.contains("allowlist"));
        assert!(!denied.contains("via Google"));

        let failed = message_page("Sign-in failed", "ab12cd34", &look);
        assert!(failed.contains("<h1>Sign-in failed</h1>"));
        assert!(failed.contains("ab12cd34"));
        assert!(!failed.contains("could not be completed"));

        let dark = Appearance { preset: Preset::Ember, mode: ColorMode::Dark, accent: Some(Rgb { r: 0x0b, g: 0x6e, b: 0x4f }) };
        let page = message_page("Unavailable", "", &dark);
        assert!(page.contains("class=\"preset-ember mode-dark\""));
        assert!(page.contains("content=\"dark\""));
        assert!(page.contains("--accent:#0b6e4f"));
        assert!(page.contains("html.mode-dark .btn.google"));
        assert!(!page.to_ascii_lowercase().contains("ship-rs"));
    }

    #[test]
    fn write_page_samples() {
        let Ok(dir) = std::env::var("SHIP_PAGE_SAMPLES") else {
            return;
        };
        let root = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&root).unwrap();
        for (name, extra) in [
            ("ink-light", "[appearance]\npreset = \"ink\"\nmode = \"light\"\n"),
            ("ember-dark", "[appearance]\npreset = \"ember\"\nmode = \"dark\"\n"),
        ] {
            let toml = format!(
                r#"
base_domain = "example.com"
tls = "internal"
auth_upstream = "127.0.0.1:8091"
admins = ["owner@example.com"]
[hub]
title = "Example sites"
deploy = "hub"
{extra}
[[sites]]
slug = "hello"
title = "Public hello"
deploy = "hello"
subdomain = "hello"
visibility = "public"
[[sites]]
slug = "notes"
title = "Protected hello"
deploy = "notes"
subdomain = "notes"
visibility = "private-listed"
allow = ["guest@example.com"]
[[sites]]
slug = "vault"
title = "Vault"
deploy = "vault"
subdomain = "vault"
visibility = "private"
allow = ["owner@example.com"]
"#
            );
            let cfg = crate::config::parse(toml.as_bytes(), std::path::Path::new("sites.toml")).unwrap();
            let look = cfg.appearance;
            std::fs::write(root.join(format!("{name}-hub-signed-out.html")), crate::generate::hub_html_for(&cfg, None)).unwrap();
            std::fs::write(root.join(format!("{name}-hub-signed-in.html")), crate::generate::hub_html_for(&cfg, Some("owner@example.com"))).unwrap();
            std::fs::write(
                root.join(format!("{name}-sign-in.html")),
                login_page(
                    &LoginView {
                        google: true,
                        github: true,
                        ret: "https://notes.example.com/",
                        bad_return: false,
                        email: "",
                        provider: "",
                        sign_out_return: "https://example.com/",
                    },
                    &look,
                ),
            )
            .unwrap();
            std::fs::write(
                root.join(format!("{name}-access-denied.html")),
                deny_page(
                    &DenyView {
                        title: "Protected hello",
                        email: "stranger@example.com",
                        provider: "Google",
                        logout_url: "https://auth.example.com/logout",
                        sign_out_return: "https://notes.example.com/",
                        switch_return: "https://auth.example.com/?return=https%3A%2F%2Fnotes.example.com%2F",
                    },
                    &look,
                ),
            )
            .unwrap();
        }
    }
}
