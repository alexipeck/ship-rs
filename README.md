# Sitegate

Sitegate serves several static sites from one Arch Linux VPS. Each site has its own subdomain. Public sites are open. Protected sites require Google or GitHub sign-in, and only the emails on that site's allowlist (plus the installation admins) get in.

The repository is the platform: the `sitegate` binary, an example manifest, and three dummy sites. A real installation keeps its own `sites.toml` and site files on the VPS, outside this repository. Nothing from a personal site is included here.

## What you get

One binary, `sitegate`, with five subcommands:

| Command | What it does |
| --- | --- |
| `serve` | Authentication service on a loopback address. Caddy calls `GET /check`. |
| `generate` | Writes a stock Caddyfile and the public hub page from `sites.toml`. |
| `deploy` | Builds a site when one has a build command, rsyncs it into its deploy directory, then generates the Caddyfile and hub. |
| `validate` | Prints the parsed installation. Allowlist emails stay out of the output. |
| `version` | Prints the version. |

Caddy itself stays stock, from Arch's `caddy` package. Sitegate does not build Caddy or load plugins.

## Language

The owner asked for Rust. The service is small and security-sensitive: cookie sealing, return-URL checks, and allowlist decisions should not depend on a garbage collector or on a large web framework. One Cargo package produces the binary, so the generator, the deploy helper, and the check service share one config parser and one release artifact.

Crates, and why these ones:

- **axum** and **tokio** serve the HTTP routes. axum is the maintained Tower-based router; the surface is six routes.
- **tower-http**'s timeout layer caps each request at 30 seconds.
- **openidconnect** performs Google's authorization-code flow with PKCE, a nonce, and ID-token verification. The `accept-string-booleans` feature accepts `email_verified` as a JSON boolean or the string `"true"`.
- **oauth2** performs GitHub's authorization-code flow with PKCE S256. The client secret goes in the token request body, which is what GitHub expects. GitHub email acceptance is a separate call to the user-emails API: exactly one primary address, and it must be verified.
- **cookie** with the `private` and `key-expansion` features seals session cookies. `PrivateJar` is AES-256-GCM. The cookie name is additional authenticated data, so a value sealed for one cookie name does not open as another. `Key::derive_from` expands a 32-byte master with HKDF.
- **serde** and **toml** parse `sites.toml`. Unknown keys are rejected.
- **notify** watches the config file's directory so an edited allowlist applies on the next request. Each read also hashes the file, so a missed watcher event still picks up a change, and a bad parse keeps the last good config.
- **reqwest** with rustls talks to the identity providers. There is no OpenSSL dependency.
- **clap** parses the subcommands.
- **idna** canonicalizes hostnames before the return-URL and allowlist checks.

`jsonwebtoken` and `rsa` exist so tests can run a local OpenID provider. The `serve` path does not call that code.

`Cargo.lock` is committed. Build with the locked set.

## Layout

| Path | Role |
| --- | --- |
| `/etc/sitegate/sites.toml` | Installation manifest. No secrets. Mode `0644`. |
| `/etc/sitegate/sitegate.env` | OAuth client secrets and the cookie key. Mode `0600`, owner root. |
| `/usr/local/bin/sitegate` | The release binary. |
| `/etc/caddy/Caddyfile` | Generated. Do not edit by hand. |
| `/srv/sitegate/hub` | Generated hub page. |
| `/srv/sitegate/sites/<slug>` | Deployed files Caddy serves. |
| `/srv/sitegate/src/<slug>` | Optional source tree the deploy command builds and syncs. |

`deploy/sites.toml.example` and `deploy/sitegate.env.example` are the templates. `examples/sites.toml` and `examples/public-hello`, `examples/protected-hello`, and `examples/spa-demo` are dummy sites for a local run. Point a production manifest at `/srv/sitegate`, not at this repository.

## Try the example

```sh
cargo build --release
cargo run --release -- deploy --config examples/sites.toml
```

The example manifest uses the internal TLS CA, HTTP `18080`, HTTPS `18443`, the auth service on `127.0.0.1:8091`, and an HTTP preview of the hub on `127.0.0.1:8742`. See [docs/install.md](docs/install.md) for the Arch install, and the other docs for OAuth, DNS, day-to-day edits, and the trust boundary.

```sh
make release
make test
```

## Docs

- [Install on Arch](docs/install.md)
- [Google and GitHub apps](docs/oauth.md)
- [DNS](docs/dns.md)
- [Sites, allowlists, and updates](docs/operations.md)
- [Security](docs/security.md)
