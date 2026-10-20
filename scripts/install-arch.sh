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
install -m 0755 target/release/sitegate /usr/local/bin/sitegate

if ! id sitegate >/dev/null 2>&1; then
  nologin=$(command -v nologin || true)
  if [ -z "$nologin" ]; then
    nologin=/usr/bin/nologin
  fi
  useradd --system --home-dir /var/lib/sitegate --create-home --shell "$nologin" sitegate
fi

install -d -m 0755 /etc/sitegate /srv/sitegate/hub /srv/sitegate/sites /srv/sitegate/src /var/lib/sitegate

if [ ! -f /etc/sitegate/sites.toml ]; then
  install -m 0644 deploy/sites.toml.example /etc/sitegate/sites.toml
fi

if [ ! -f /etc/sitegate/sitegate.env ]; then
  key=$(openssl rand -base64 32 | tr -d '\n')
  umask 077
  awk -v key="$key" '
    BEGIN { FS = OFS = "=" }
    $1 == "SITEGATE_COOKIE_KEY" && $2 == "" { $2 = key }
    { print }
  ' deploy/sitegate.env.example > /etc/sitegate/sitegate.env
  chmod 0600 /etc/sitegate/sitegate.env
  chown root:root /etc/sitegate/sitegate.env
fi

install -m 0644 deploy/sitegate.service /etc/systemd/system/sitegate.service
systemctl daemon-reload

echo "installed $(/usr/local/bin/sitegate version)"
echo "edit /etc/sitegate/sites.toml and /etc/sitegate/sitegate.env"
echo "then: systemctl enable --now sitegate"
echo "then: sitegate deploy --config /etc/sitegate/sites.toml --reload"
