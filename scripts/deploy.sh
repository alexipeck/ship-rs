#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

config=${1:-${SHIP_CONFIG:-}}
if [ -z "$config" ]; then
  echo "usage: scripts/deploy.sh /etc/ship-rs/sites.toml" >&2
  exit 2
fi

if [ ! -x target/release/ship-rs ]; then
  cargo build --release
fi

exec target/release/ship-rs deploy --config "$config" --reload
