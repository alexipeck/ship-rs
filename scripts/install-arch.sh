#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run scripts/install-arch.sh as root" >&2
  exit 1
fi

if ! command -v pacman >/dev/null 2>&1; then
  echo "scripts/install-arch.sh expects Arch Linux (pacman)" >&2
  exit 1
fi

pacman -S --needed --noconfirm caddy rsync openssl

if ! command -v cargo >/dev/null 2>&1; then
  echo "install rustup, then re-run: https://rustup.rs" >&2
  exit 1
fi

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
cargo build --release
install -m 0755 target/release/ship-rs /usr/local/bin/ship-rs

if ! id ship-rs >/dev/null 2>&1; then
  nologin=$(command -v nologin || true)
  if [ -z "$nologin" ]; then
    nologin=/usr/bin/nologin
  fi
  useradd --system --home-dir /var/lib/ship-rs --create-home --shell "$nologin" ship-rs
fi

install -d -m 0755 /etc/ship-rs /srv/ship-rs/hub /srv/ship-rs/sites /srv/ship-rs/src /var/lib/ship-rs

if [ ! -f /etc/ship-rs/sites.toml ]; then
  install -m 0644 deploy/sites.toml.example /etc/ship-rs/sites.toml
fi

if [ ! -f /etc/ship-rs/ship-rs.env ]; then
  key=$(openssl rand -base64 32 | tr -d '\n')
  umask 077
  awk -v key="$key" '
    BEGIN { FS = OFS = "=" }
    $1 == "SHIP_COOKIE_KEY" && $2 == "" { $2 = key }
    { print }
  ' deploy/ship.env.example > /etc/ship-rs/ship-rs.env
  chmod 0600 /etc/ship-rs/ship-rs.env
  chown root:root /etc/ship-rs/ship-rs.env
fi

install -m 0644 deploy/ship.service /etc/systemd/system/ship-rs.service
systemctl daemon-reload

echo "installed $(/usr/local/bin/ship-rs version)"
echo "edit /etc/ship-rs/sites.toml and /etc/ship-rs/ship-rs.env"
echo "then: systemctl enable --now ship-rs"
echo "then: ship-rs deploy --config /etc/ship-rs/sites.toml --reload"
