#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

config=${1:-${SITEGATE_CONFIG:-}}
if [ -z "$config" ]; then
  echo "usage: scripts/deploy.sh /etc/sitegate/sites.toml" >&2
  exit 2
fi

if [ ! -x target/release/sitegate ]; then
  cargo build --release
fi

exec target/release/sitegate deploy --config "$config" --reload
