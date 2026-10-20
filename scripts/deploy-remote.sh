#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: scripts/deploy-remote.sh [-p PORT] [-i IDENTITY] user@host

Copy the committed x86_64-unknown-linux-gnu binary to an Arch Linux server
and install the ship-rs service, the three dummy example sites, and
/etc/ship-rs/sites.toml. An existing sites.toml or ship-rs.env is left
in place. The firewall is not changed, and Caddy is not started.

  -p, --port       SSH port
  -i, --identity   SSH private key
  -h, --help       Show this help

Set SHIP_RS_YES=1 to skip the confirmation prompt.
EOF
}

port=""
identity=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -p|--port)
      if [ -z "${2:-}" ]; then
        echo "missing port" >&2
        exit 2
      fi
      port=$2
      shift 2
      ;;
    -i|--identity)
      if [ -z "${2:-}" ]; then
        echo "missing identity file" >&2
        exit 2
      fi
      identity=$2
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      break
      ;;
  esac
done

target=${1:-}
if [ -z "$target" ] || [ "$#" -ne 1 ]; then
  usage >&2
  exit 2
fi

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
binary="$root/prebuilt/ship-rs"
checksum="$root/prebuilt/ship-rs.sha256"
if [ ! -f "$binary" ] || [ ! -f "$checksum" ]; then
  echo "missing $binary" >&2
  echo "the prebuilt binary is part of this checkout" >&2
  exit 1
fi

file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

version_at_least() {
  need=$1
  have=$2
  awk -v need="$need" -v have="$have" 'BEGIN {
    split(need, a, ".")
    split(have, b, ".")
    for (i = 1; i <= 3; i++) {
      av = a[i] + 0
      bv = b[i] + 0
      if (bv > av) exit 0
      if (bv < av) exit 1
    }
    exit 0
  }'
}

expected=$(tr -d '[:space:]' < "$checksum")
actual=$(file_sha256 "$binary")
if [ "$expected" != "$actual" ]; then
  echo "prebuilt/ship-rs does not match prebuilt/ship-rs.sha256" >&2
  exit 1
fi

run_ssh() {
  if [ -n "$port" ] && [ -n "$identity" ]; then
    ssh -o ConnectTimeout=20 -p "$port" -i "$identity" "$@"
  elif [ -n "$port" ]; then
    ssh -o ConnectTimeout=20 -p "$port" "$@"
  elif [ -n "$identity" ]; then
    ssh -o ConnectTimeout=20 -i "$identity" "$@"
  else
    ssh -o ConnectTimeout=20 "$@"
  fi
}

echo "Checking $target"
remote_info=$(run_ssh "$target" 'printf "machine %s\n" "$(uname -m)"; . /etc/os-release; printf "os %s\n" "$ID"; printf "uid %s\n" "$(id -u)"; if command -v pacman >/dev/null 2>&1; then echo pacman yes; else echo pacman no; fi; ldd --version | awk "NR==1 { printf \"glibc %s\\n\", \$NF }"')
machine=$(printf '%s\n' "$remote_info" | awk '$1=="machine" { print $2 }')
os_id=$(printf '%s\n' "$remote_info" | awk '$1=="os" { print $2 }')
remote_uid=$(printf '%s\n' "$remote_info" | awk '$1=="uid" { print $2 }')
remote_pacman=$(printf '%s\n' "$remote_info" | awk '$1=="pacman" { print $2 }')
remote_glibc=$(printf '%s\n' "$remote_info" | awk '$1=="glibc" { print $2 }')

echo "  arch: $machine"
echo "  os: $os_id"
echo "  uid: $remote_uid"
echo "  glibc: $remote_glibc"

if [ "$machine" != "x86_64" ]; then
  echo "refusing to install: binary is x86_64-unknown-linux-gnu" >&2
  exit 1
fi
if [ "$os_id" != "arch" ] || [ "$remote_pacman" != "yes" ]; then
  echo "refusing to install: server is not Arch Linux" >&2
  exit 1
fi
if ! version_at_least 2.39 "$remote_glibc"; then
  echo "refusing to install: glibc $remote_glibc is older than 2.39" >&2
  exit 1
fi

if [ -t 0 ]; then
  printf 'Install ship-rs on %s? [y/N] ' "$target"
  read -r ans || exit 1
  case "$ans" in
    y|Y|yes|YES) ;;
    *)
      echo "cancelled"
      exit 1
      ;;
  esac
elif [ "${SHIP_RS_YES:-}" != "1" ]; then
  echo "set SHIP_RS_YES=1 to install without a prompt" >&2
  exit 2
fi

remote=$(run_ssh "$target" 'd=$(mktemp -d /tmp/ship-rs-bootstrap.XXXXXX); printf "SHIP_RS_DIR %s\n" "$d"' | awk '$1=="SHIP_RS_DIR" { print $2 }')
case "$remote" in
  /tmp/ship-rs-bootstrap.*) ;;
  *)
    echo "unexpected remote directory: $remote" >&2
    exit 1
    ;;
esac

echo "Uploading binary and example sites to $remote"
archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
tar -C "$root" -czf "$archive" \
  prebuilt/ship-rs \
  prebuilt/ship-rs.sha256 \
  examples/public-hello \
  examples/protected-hello \
  examples/spa-demo \
  deploy/ship-rs.service \
  deploy/ship-rs.env.example \
  deploy/sites.arch.toml \
  scripts/remote-bootstrap.sh
run_ssh "$target" "tar -xzf - -C '$remote'" < "$archive"

status=0
if [ "$remote_uid" -eq 0 ]; then
  run_ssh "$target" "sh '$remote/scripts/remote-bootstrap.sh' '$remote'" || status=$?
else
  run_ssh -t "$target" "sudo sh '$remote/scripts/remote-bootstrap.sh' '$remote'" || status=$?
fi

if [ "$status" -eq 0 ]; then
  run_ssh "$target" "rm -rf '$remote'"
else
  echo "install failed; files remain on the server in $remote" >&2
fi
exit "$status"
