# Security

ship-rs's job is to keep anonymous and unlisted accounts out of protected sites, and to keep a request from choosing its own identity. The mechanisms below are what the binary and the generated Caddyfile actually do.

## Who may read a protected site

`/check` looks at the session cookie and `X-Forwarded-Host`. The decision is:

- The host is not an enabled site: 403.
- The site is public: 200, and no identity header.
- The cookie is missing, expired, or does not open: 401.
- The email is on that site's allowlist, or is an admin: 200 and `X-Ship-Rs-Email`.
- Otherwise: 403.

The email in the cookie is the whole identity. The cookie does not carry a role or a list of sites. Changing `sites.toml` changes the decision on the next request.

Google must set `email_verified` to JSON `true` or the string `"true"`. GitHub must return exactly one primary email, and it must be verified. The access token is used for that one request and is not stored.

## Cookies

The session cookie is `ship-rs_session`. It is `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, and `Domain` is the base domain with no leading dot. The payload is email, provider, issued-at, and expiry. It is sealed with the cookie crate's private jar: AES-256-GCM, with the cookie name as additional authenticated data. A value sealed under another name, a flipped ciphertext, a cookie from a different key, a lifetime longer than the configured TTL, a future issued-at, or an expiry does not open.

The OAuth state cookie is `__Host-ship-rs_oauth`. It is host-only (no `Domain`), `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`, and it lives for 10 minutes. It holds the state, the PKCE verifier, the nonce, the provider, and the return URL. State is compared in constant time. The verifier never goes in the query string.

Both jars are keyed from `SHIP_COOKIE_KEY` (32 bytes, base64 or hex). The process refuses an all-zero key. `SHIP_COOKIE_KEY_PREVIOUS` opens old cookies and is never used to seal a new one.

Because `Domain` is the apex, the browser sends the session cookie to every subdomain. `HttpOnly` stops page scripts from reading it. Do not enable CORS on a protected site, and do not host untrusted content on a subdomain of the same apex: that origin can already send the cookie to Caddy. A sibling subdomain can also submit the sign-out form, because logout accepts any HTTPS origin under the base domain. That signs the browser out. It does not reveal the cookie or grant access.

## Headers

The generated Caddyfile deletes client-supplied identity headers before `forward_auth` and again on the way upstream: `X-Ship-Rs-Email`, `X-Ship-Rs-Provider`, `Remote-User`, `Remote-Email`, `Remote-Name`, `Remote-Groups`, `X-Remote-User`, `X-Forwarded-User`, and `X-Forwarded-Email`. The response path strips the same names. `/check` sets `X-Ship-Rs-Email` only after a successful allow, and Caddy copies that one header.

There is no shared secret between Caddy and `/check`. The trust boundary is the loopback listener plus Caddy being the only client that should reach it. Do not publish `127.0.0.1:8091`, and do not set `trusted_proxies` so that a visitor can supply `X-Forwarded-Host`. The service binds loopback and checks the address again after the socket is open.

`forward_auth` runs inside a `route` block, before `try_files`, so a client route on a protected SPA is still authenticated. `X-Forwarded-Uri` must start with a single `/`. `X-Forwarded-Proto` must be `https` for a return URL built from the forwarded request.

## Redirects

Login does not start by itself when someone opens a protected site. The 401 page links to the auth host. The return URL is checked again when the flow starts and again when it finishes. The callback URL is the configured auth origin plus `/callback/google` or `/callback/github`. A `Host` header cannot move the token exchange.

Provider HTTP redirects are limited and must stay on the same host. `SHIP_ALLOW_UNSAFE_OAUTH_OVERRIDES` is off unless set to `1`. Leave it off.

Auth pages send `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, plus `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, and `Cache-Control: no-store`. Gate pages use the same policy with `form-action` pointed at the auth origin. The pages contain no meta refresh and no script redirect.

Login failures return a short reference. Logs do not include cookie values, authorization codes, or tokens. A successful login logs the provider and the email.

## Files on disk

Deployed files are mode `0644` and directories `0755` so the `caddy` user can read them. That is not confidentiality on the machine. Anyone who can read the disk can read a protected site's files. HTTP auth is the network control. If the VPS is shared, add an ACL so only `caddy` and the deploying user can read `/srv/ship-rs/sites/<protected-slug>`, and keep the source tree out of any public clone.

`sites.toml` is `0644` and contains emails. `ship-rs.env` is `0600` and owned by root. A world-readable env file is logged as a warning when `serve --env-file` loads it. Prefer systemd's `EnvironmentFile` over `--env-file`.

## Tests that lock this in

Unit tests cover allow and admin decisions, a reload that drops an email without a restart, a bad reload that keeps the previous manifest, tampered and expired cookies, and return-URL rejection. An integration test starts this binary, stock Caddy 2.11, and a local mock provider, then checks public and protected responses, both login flows, a stranger, an admin, a tampered cookie, a spoofed identity header, a spoofed `X-Forwarded-Host`, the `www` redirect, a live allowlist edit, a broken manifest, logout, and an open-redirect attempt.
