# Operations

Every command takes the installation manifest. The binary does not assume a path except the systemd unit, which passes `/etc/sitegate/sites.toml`.

```sh
sitegate validate --config /etc/sitegate/sites.toml
sitegate generate --config /etc/sitegate/sites.toml
sitegate deploy --config /etc/sitegate/sites.toml --reload
```

`SITEGATE_CONFIG` fills in `--config` when the flag is absent. `--caddyfile` and `--hub` override the paths in the manifest for one invocation.

## Manifest

`deploy/sites.toml.example` is the production template. Unknown keys are a parse error. The fields that matter:

| Field | Meaning |
| --- | --- |
| `base_domain` | Apex, such as `example.com`. |
| `acme_email` | Contact for Let's Encrypt when `tls = "auto"`. |
| `tls` | `auto` (default) or `internal`. |
| `http_port`, `https_port` | Default 80 and 443. They must differ. |
| `auth_upstream` | Loopback address of `sitegate serve`. Default `127.0.0.1:8091`. |
| `caddyfile` | Where `generate` writes the Caddyfile. |
| `caddy_admin` | Empty uses Caddy's localhost admin port. `off` disables it. Any other value must be loopback. |
| `preview_addr` | Optional loopback address. Caddy serves only the hub there, over HTTP. |
| `admins` | Emails allowed on every protected site. |
| `hub.title`, `hub.deploy` | Hub heading and the directory that receives `index.html`. |
| `sites` | One table per site. |

Each site needs `slug`, `title`, `deploy`, `subdomain`, and `public`. `enabled` defaults to true. `spa` and `unlisted` default to false. `source` is the directory `deploy` syncs from. `build` is an optional shell command, at most 2000 characters and without newlines, run in that directory before the sync. `allow` is the email list for a protected site.

Slugs, subdomains, and deploy paths are unique. The hub deploy path counts as used. Subdomains `auth` and `www` are reserved. Titles are 1–80 characters and cannot contain a newline or `<` or `>`. Relative paths are resolved from the directory that holds `sites.toml`. Paths that contain spaces, quotes, or shell metacharacters are rejected so they can be pasted into a Caddyfile safely.

`public = true` serves the deploy directory with no authentication. `public = false` sends the request through `forward_auth` to `/check`. `spa = true` adds `try_files {path} /index.html` so a client route still returns the site. `enabled = false` omits the site from Caddy and from the hub. `unlisted = true` keeps an enabled site off the hub.

The hub is public. It lists enabled public sites, and enabled protected sites with a “Sign-in required” badge, in manifest order. It does not print allowlists or admin addresses. Disabled sites are omitted.

## Add a site

Put the files on the VPS, not in this repository. For a site that is already built:

```sh
sudo install -d -m 0755 /srv/sitegate/sites/notes
sudo rsync -a ./dist/ /srv/sitegate/sites/notes/
```

Or set `source` (and maybe `build`) and let `sitegate deploy` run the command and rsync. A protected tree:

```toml
[[sites]]
slug = "notes"
title = "Notes"
source = "/srv/sitegate/src/notes"
deploy = "/srv/sitegate/sites/notes"
subdomain = "notes"
public = false
allow = ["guest@example.com"]
```

Then:

```sh
sudo sitegate deploy --config /etc/sitegate/sites.toml --reload
```

Deploy runs `rsync -a --delete --safe-links` from `source/` to `deploy/`, then sets directories to `0755` and regular files to `0644` so the `caddy` user can read them. Symlinks are left alone. It rewrites the hub and the Caddyfile by writing a temporary file, syncing it, and renaming it into place.

Protected files must not be pushed to a public remote. The deploy directory on the VPS is the only copy the web server needs.

## Allowlists and admins

Emails are stored lowercase. `guest@example.com` and `Guest@Example.com` are the same account.

Admins are in the top-level `admins` list. An admin may open every protected site, whether or not the site's `allow` list names them.

Edit the list in `/etc/sitegate/sites.toml` and save. The running process re-reads the file. The next `/check` uses the new list. You do not reload Caddy and you do not restart `sitegate`. If the file is unreadable or invalid, the process logs the failure once for that content and keeps serving the last good manifest.

Removing an email takes effect the same way: the next request from that account is denied.

## What a visitor sees

Opening a protected site while signed out does not bounce the browser to Google or GitHub. Caddy returns the sign-in page from `/check`, with one button that goes to `https://auth.example.com/?return=...`. After a successful login the browser returns to the original URL.

The return address has to be `https`, at most 2048 characters, with no userinfo and no newline or backslash. The host must be the apex or a subdomain of `base_domain`. Anything else is a 400 and is not echoed back.

A signed-in account that is not on the list sees an access-denied page that names the account and offers sign-out and a switch to another account. Requests that do not look like a document navigation get a plain `401 Sign in required` or `403 Access denied` with no HTML and no `Location` header.

Sign-out is `POST /logout`. The `Origin` or `Referer` must be HTTPS on the apex or a subdomain. A bad origin is `403` and the cookie is left in place.

## Updates

```sh
sudo pacman -Syu caddy rsync
rustup update stable
git pull
cargo build --release
sudo install -m 0755 target/release/sitegate /usr/local/bin/sitegate
sudo systemctl restart sitegate
sudo sitegate deploy --config /etc/sitegate/sites.toml --reload
```

Restart `sitegate` when the binary or the env file changes. Reload Caddy when the Caddyfile changes. An allowlist-only edit needs neither.

To rotate the cookie key, set `SITEGATE_COOKIE_KEY_PREVIOUS` to the old value, put the new value in `SITEGATE_COOKIE_KEY`, and restart. Existing sessions still open. New sessions are sealed with the new key. Remove the previous key on a later restart.

`sitegate validate` prints the domain, ports, auth origin, admin addresses, and each site's access mode and allowlist size. It does not print the allowlist itself.
