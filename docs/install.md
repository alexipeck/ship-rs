# Install on Arch Linux

Sitegate is a single Rust binary plus stock Caddy. The binary is built with rustup and cargo. Arch's `caddy` and `rsync` packages come from the official repositories. Do not install a custom Caddy build.

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
sudo install -m 0755 target/release/sitegate /usr/local/bin/sitegate
sitegate version
```

`cargo build --release` reads `Cargo.lock`. The binary has no runtime dependency on the Rust toolchain. After it is installed, the VPS only needs Caddy, rsync, and `sitegate`.

`scripts/install-arch.sh` does the same steps when run as root on a machine with `pacman`: it installs `caddy` and `rsync`, builds the release binary, installs it to `/usr/local/bin/sitegate`, creates the `sitegate` system user, and installs the systemd unit. It does not overwrite an existing `/etc/sitegate/sites.toml` or `/etc/sitegate/sitegate.env`.

## Files

```sh
sudo install -d -m 0755 /etc/sitegate /srv/sitegate/hub /srv/sitegate/sites /srv/sitegate/src
sudo install -m 0644 deploy/sites.toml.example /etc/sitegate/sites.toml
sudo install -m 0600 deploy/sitegate.env.example /etc/sitegate/sitegate.env
```

Edit `/etc/sitegate/sites.toml` and set `base_domain`, `acme_email`, `admins`, and the sites you actually host. Real site files belong under `/srv/sitegate`. Leave them out of any git checkout of this repository.

Generate a cookie key and put it in the env file:

```sh
openssl rand -base64 32
```

`SITEGATE_COOKIE_KEY` is 32 bytes, encoded as standard base64 (padding optional) or as hex. An all-zero key is rejected. The env file stays mode `0600` and owned by root. systemd reads `EnvironmentFile` before it drops privileges. The `sitegate` user never needs to read that file, and the TOML file never contains a client secret or the cookie key.

Fill in the Google and GitHub client id and secret. The callback URLs are in [oauth.md](oauth.md). `SITEGATE_SESSION_TTL` defaults to `12h` and must sit between `5m` and `168h`.

## User and unit

```sh
sudo useradd --system --home-dir /var/lib/sitegate --create-home --shell /usr/bin/nologin sitegate
sudo install -m 0644 deploy/sitegate.service /etc/systemd/system/sitegate.service
sudo systemctl daemon-reload
sudo systemctl enable --now sitegate
sudo systemctl status sitegate
```

The unit runs `sitegate serve --config /etc/sitegate/sites.toml` as user `sitegate`. It listens only on the loopback address in `auth_upstream` (default `127.0.0.1:8091`). `SITEGATE_LISTEN`, if set, must be that same address.

The unit sets `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, an empty capability set, and `UMask=0077`. `RestrictAddressFamilies` allows `AF_INET`, `AF_INET6`, and `AF_UNIX`. The UNIX family is there so glibc name service can talk to systemd-resolved. `MemoryDenyWriteExecute` is omitted so process startup is not coupled to a filter that rejects the runtime's executable mappings. `ReadOnlyPaths=/etc/sitegate` covers the manifest.

Confirm the listener:

```sh
curl -fsS http://127.0.0.1:8091/healthz
```

## Caddy

Enable Caddy after the first generate, and after DNS answers for the names in the manifest:

```sh
sudo sitegate validate --config /etc/sitegate/sites.toml
sudo sitegate deploy --config /etc/sitegate/sites.toml
sudo systemctl enable --now caddy
sudo systemctl reload caddy
```

`deploy --reload` runs `systemctl reload caddy` for you. Leave Caddy's admin endpoint on localhost. The example manifest sets `caddy_admin = "off"` so a laptop run does not bind port 2019. A production manifest should leave `caddy_admin` unset so `systemctl reload` can reach the admin API. Do not set `caddy_admin` to a public address.

`scripts/deploy.sh /etc/sitegate/sites.toml` builds the release binary when `target/release/sitegate` is missing, then runs `deploy --reload`.

## Local example

The example manifest is not an installation. It uses internal certificates and high ports so it can run beside a real web server:

```sh
cargo run --release -- deploy --config examples/sites.toml
```

That writes `examples/dist/` (gitignored): the Caddyfile, the hub, and copies of the three dummy sites. To look at the hub over plain HTTP, run Caddy against `examples/dist/Caddyfile` and open `http://127.0.0.1:8742`. The auth service for that manifest is `127.0.0.1:8091`. Sign-in cookies are `Secure`, so a full Google or GitHub round trip needs HTTPS on `auth.example.com` and a hosts entry, not the preview port.
