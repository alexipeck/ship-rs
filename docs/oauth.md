# Google and GitHub

The sign-in buttons are the only login UI. Sitegate asks Google for `openid` and `email`, and GitHub for `user:email`. It keeps an address only when the provider says that address is verified. Comparison is case-insensitive.

The callback URL is derived from `sites.toml`, not from the request's Host header. With `base_domain = "example.com"` and `https_port` left at 443, register these exact URLs:

- `https://auth.example.com/callback/google`
- `https://auth.example.com/callback/github`

If `https_port` is not 443, the port is part of the origin (`https://auth.example.com:18443/callback/google` in the example manifest). Changing the domain or the HTTPS port means registering the new URLs at Google and GitHub before the next login.

## Google

1. In Google Cloud Console, create or select a project.
2. Configure the OAuth consent screen. Add the `email` and `openid` scopes. While the app is in testing, add every human who will sign in as a test user.
3. Create an OAuth client of type **Web application**.
4. Under Authorized redirect URIs, add `https://auth.example.com/callback/google` and nothing broader.
5. Copy the client id and client secret into `/etc/sitegate/sitegate.env`:

```
SITEGATE_GOOGLE_CLIENT_ID=....apps.googleusercontent.com
SITEGATE_GOOGLE_CLIENT_SECRET=...
```

Sitegate discovers `https://accounts.google.com`, sends a PKCE S256 challenge and a nonce, and verifies the ID token against Google's keys. `email_verified` must be JSON `true` or the string `"true"`. An unverified address is refused.

## GitHub

1. In GitHub, open Settings → Developer settings → OAuth Apps → New OAuth App. This is an OAuth App, not a GitHub App.
2. Homepage URL: `https://example.com`.
3. Authorization callback URL: `https://auth.example.com/callback/github`.
4. Copy the client id and generate a client secret into the env file:

```
SITEGATE_GITHUB_CLIENT_ID=...
SITEGATE_GITHUB_CLIENT_SECRET=...
```

After the token exchange, Sitegate calls `GET https://api.github.com/user/emails` with the access token. It accepts the account only when the response contains exactly one primary email and that email is verified. A verified secondary address is not used. The request sends `User-Agent: sitegate` and `Accept: application/vnd.github+json`, and it will not follow a redirect off GitHub's host.

## Both providers, or one

Set both halves of a provider or neither. A half-set pair is a startup error. With neither provider set, the process still serves `/check` and the hub, and the login page says sign-in is not configured.

Restart the service after an env change:

```sh
sudo systemctl restart sitegate
```

Allowlist edits do not need a restart. See [operations.md](operations.md).

## Overrides

`SITEGATE_OIDC_ISSUER`, `SITEGATE_GITHUB_AUTH_URL`, `SITEGATE_GITHUB_TOKEN_URL`, and `SITEGATE_GITHUB_EMAILS_URL` replace the provider endpoints. Sitegate refuses to start when any of them differ from the defaults unless `SITEGATE_ALLOW_UNSAFE_OAUTH_OVERRIDES=1`. Even then, an `http` URL is accepted only for loopback. Leave the overrides unset on the VPS. They exist so tests can point at a local mock.
