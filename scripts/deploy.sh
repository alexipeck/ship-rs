#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

config=${1:-${SHIP_CONFIG:-}}
if [ -z "$config" ]; then
  echo "usage: scripts/deploy.sh /etc/ship-rs/sites.toml" >&2
  echo "This updates sites on the machine where it is run." >&2
  echo "To install onto a VPS from this checkout: scripts/deploy-remote.sh user@host" >&2
  exit 2
fi
case "$config" in
  *@*)
    echo "scripts/deploy.sh does not take an SSH address." >&2
    echo "Run: scripts/deploy-remote.sh $config" >&2
    exit 2
    ;;
esac

if [ ! -x target/release/ship-rs ] && [ ! -f target/release/ship-rs.exe ]; then
  cargo build --release
fi
if [ -x target/release/ship-rs ]; then
  bin=target/release/ship-rs
elif [ -f target/release/ship-rs.exe ]; then
  bin=target/release/ship-rs.exe
else
  echo "no release binary at target/release/ship-rs" >&2
  exit 1
fi

exec "$bin" deploy --config "$config" --reload
