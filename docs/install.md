# Install on Arch Linux

ship-rs is a single Rust binary plus stock Caddy. The binary is built with rustup and cargo. Arch's `caddy` and `rsync` packages come from the official repositories. Do not install a custom Caddy build.

## Packages

```sh
sudo pacman -S --needed caddy rsync openssl
```

Install Rust with rustup, then use the stable toolchain:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup default stable
```

The crate graph needs rustc 1.85 or newer. `Cargo.toml` records that floor.

## Build

From a checkout of this repository:

```sh
cargo build --release
sudo install -m 0755 target/release/ship-rs /usr/local/bin/ship-rs
ship-rs version
```

`cargo build --release` reads `Cargo.lock`. The binary has no runtime dependency on the Rust toolchain. After it is installed, the VPS only needs Caddy, rsync, and `ship-rs`.

`scripts/install-arch.sh` does the same steps when run as root on a machine with `pacman`: it installs `caddy` and `rsync`, builds the release binary, installs it to `/usr/local/bin/ship-rs`, creates the `ship-rs` system user, and installs the systemd unit. It does not overwrite an existing `/etc/ship-rs/sites.toml` or `/etc/ship-rs/ship-rs.env`.

## Files

```sh
sudo install -d -m 0755 /etc/ship-rs /srv/ship-rs/hub /srv/ship-rs/sites /srv/ship-rs/src
sudo install -m 0644 deploy/sites.toml.example /etc/ship-rs/sites.toml
sudo install -m 0600 deploy/ship.env.example /etc/ship-rs/ship-rs.env
```

Edit `/etc/ship-rs/sites.toml` and set `base_domain`, `acme_email`, `admins`, and the sites you actually host. Real site files belong under `/srv/ship-rs`. Leave them out of any git checkout of this repository.

Generate a cookie key and put it in the env file:

```sh
openssl rand -base64 32
```

`SHIP_COOKIE_KEY` is 32 bytes, encoded as standard base64 (padding optional) or as hex. An all-zero key is rejected. The env file stays mode `0600` and owned by root. systemd reads `EnvironmentFile` before it drops privileges. The `ship-rs` user never needs to read that file, and the TOML file never contains a client secret or the cookie key.

Fill in the Google and GitHub client id and secret. The callback URLs are in [oauth.md](oauth.md). `SHIP_SESSION_TTL` defaults to `12h` and must sit between `5m` and `168h`.

## User and unit

```sh
sudo useradd --system --home-dir /var/lib/ship-rs --create-home --shell /usr/bin/nologin ship-rs
sudo install -m 0644 deploy/ship.service /etc/systemd/system/ship-rs.service
sudo systemctl daemon-reload
sudo systemctl enable --now ship-rs
sudo systemctl status ship-rs
```

The unit runs `ship-rs serve --config /etc/ship-rs/sites.toml` as user `ship-rs`. It listens only on the loopback address in `auth_upstream` (default `127.0.0.1:8091`). `SHIP_LISTEN`, if set, must be that same address.

The unit sets `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, an empty capability set, and `UMask=0077`. `RestrictAddressFamilies` allows `AF_INET`, `AF_INET6`, and `AF_UNIX`. The UNIX family is there so glibc name service can talk to systemd-resolved. `MemoryDenyWriteExecute` is omitted so process startup is not coupled to a filter that rejects the runtime's executable mappings. `ReadOnlyPaths=/etc/ship-rs` covers the manifest.

Confirm the listener:

```sh
curl -fsS http://127.0.0.1:8091/healthz
```

## Caddy

Enable Caddy after the first generate, and after DNS answers for the names in the manifest:

```sh
sudo ship-rs validate --config /etc/ship-rs/sites.toml
sudo ship-rs deploy --config /etc/ship-rs/sites.toml
sudo systemctl enable --now caddy
sudo systemctl reload caddy
```

`deploy --reload` runs `systemctl reload caddy` for you. Leave Caddy's admin endpoint on localhost. The example manifest sets `caddy_admin = "off"` so a laptop run does not bind port 2019. A production manifest should leave `caddy_admin` unset so `systemctl reload` can reach the admin API. Do not set `caddy_admin` to a public address.

`scripts/deploy.sh /etc/ship-rs/sites.toml` builds the release binary when `target/release/ship-rs` is missing, then runs `deploy --reload`.

## Install from your own machine

`prebuilt/ship` is the `x86_64-unknown-linux-gnu` release binary (glibc 2.39 or newer). From a checkout on a computer that can already SSH to the VPS:

```sh
scripts/deploy-remote.sh user@203.0.113.10
scripts/deploy-remote.sh -p 22 -i ~/.ssh/id_ed25519 user@203.0.113.10
```

The script checks that the server is x86_64 Arch with a new enough glibc, copies the binary, installs Caddy, rsync, and OpenSSL, creates the `ship-rs` user, and starts the loopback service. It copies the three dummy sites into `/srv/ship-rs/src` and `/srv/ship-rs/sites`, and writes `/etc/ship-rs/sites.toml` from `deploy/sites.arch.toml` when that file is not already there. A cookie key is generated in `/etc/ship-rs/ship-rs.env` on first install. An existing manifest or env file is left untouched.

It does not open firewall ports and it does not start Caddy. Edit `base_domain`, `acme_email`, and `admins` in `/etc/ship-rs/sites.toml`, put the OAuth client id and secret in the env file, restart `ship-rs`, then run `ship-rs deploy --config /etc/ship-rs/sites.toml --reload` and `systemctl enable --now caddy`.

## Local example

The example manifest is not an installation. It uses internal certificates and high ports so it can run beside a real web server:

```sh
cargo run --release -- deploy --config examples/sites.toml
```

That writes `examples/dist/` (gitignored): the Caddyfile, the hub, and copies of the three dummy sites. To look at the hub over plain HTTP, run Caddy against `examples/dist/Caddyfile` and open `http://127.0.0.1:8742`. The auth service for that manifest is `127.0.0.1:8091`. Sign-in cookies are `Secure`, so a full Google or GitHub round trip needs HTTPS on `auth.example.com` and a hosts entry, not the preview port.
