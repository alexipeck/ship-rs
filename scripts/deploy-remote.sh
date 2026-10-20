#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: scripts/deploy-remote.sh [-p PORT] [-i IDENTITY] [-b] [--regen] user@host

Run this from a checkout of the repo, on Linux, macOS, WSL, or Git Bash.
It SSHes to an Arch Linux server, installs the Linux ship-rs binary, the
example sites, and /etc/ship-rs/sites.toml, and writes /etc/caddy/Caddyfile.
An existing sites.toml or ship-rs.env is left in place. The firewall is
not changed. Caddy is started only when base_domain is not example.com.

OpenSSH must be on your PATH. Pass -i when the key is not your SSH default.

  -p, --port         SSH port
  -i, --identity     SSH private key
  -b, --binary-only  Replace /usr/local/bin/ship-rs and restart ship-rs.service.
                     Does not change sites.toml, ship-rs.env, site files, the
                     systemd unit, or packages.
  --regen            With --binary-only, after healthz succeeds, run
                     ship-rs generate --config /etc/ship-rs/sites.toml and
                     systemctl reload caddy.
  -h, --help         Show this help

A binary built with cargo on Windows is ship-rs.exe and cannot run on the
VPS. The script uploads, in order, the first ELF it finds:

  target/x86_64-unknown-linux-gnu/release/ship-rs
  target/release/ship-rs
  prebuilt/ship

Set SHIP_YES=1 to skip the confirmation prompt.
EOF
}

port=""
identity=""
binary_only=0
regen=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -b|--binary-only)
      binary_only=1
      shift
      ;;
    --regen)
      regen=1
      shift
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

if [ "$regen" -eq 1 ] && [ "$binary_only" -ne 1 ]; then
  echo "--regen requires --binary-only" >&2
  exit 2
fi

target=${1:-}
if [ -z "$target" ] || [ "$#" -ne 1 ]; then
  usage >&2
  exit 2
fi

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

if ! command -v ssh >/dev/null 2>&1; then
  echo "ssh is not on PATH. Install OpenSSH, then re-run." >&2
  exit 1
fi
if ! command -v tar >/dev/null 2>&1; then
  echo "tar is not on PATH." >&2
  exit 1
fi

is_elf() {
  [ -f "$1" ] || return 1
  command -v od >/dev/null 2>&1 || return 1
  sig=$(od -An -t x1 -N 4 "$1" 2>/dev/null | tr -d ' \n')
  [ "$sig" = "7f454c46" ]
}

file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  else
    echo "need sha256sum or shasum to check the binary" >&2
    return 1
  fi
}

binary=""
for candidate in \
  "$root/target/x86_64-unknown-linux-gnu/release/ship-rs" \
  "$root/target/release/ship-rs" \
  "$root/prebuilt/ship"
do
  if is_elf "$candidate"; then
    binary=$candidate
    break
  fi
done
if [ -z "$binary" ]; then
  echo "no Linux ship-rs binary found." >&2
  if [ -f "$root/target/release/ship-rs.exe" ]; then
    echo "target/release/ship-rs.exe is a Windows build and cannot run on the VPS." >&2
  fi
  echo "Cross-compile with: cargo build --release --target x86_64-unknown-linux-gnu" >&2
  echo "or use the Linux binary shipped at prebuilt/ship." >&2
  exit 1
fi
echo "Using binary $binary"
if [ "$binary" = "$root/prebuilt/ship" ]; then
  checksum="$root/prebuilt/ship.sha256"
  if [ ! -f "$checksum" ]; then
    echo "missing $checksum" >&2
    exit 1
  fi
  expected=$(tr -d '[:space:]' < "$checksum")
  actual=$(file_sha256 "$binary")
  if [ "$expected" != "$actual" ]; then
    echo "prebuilt/ship does not match prebuilt/ship.sha256" >&2
    exit 1
  fi
  if [ -f "$root/target/release/ship-rs.exe" ]; then
    echo "Ignoring target/release/ship-rs.exe. That build is for Windows."
  fi
fi

if [ -n "$identity" ] && [ -n "${MSYSTEM:-}" ] && command -v cygpath >/dev/null 2>&1; then
  identity=$(cygpath -w "$identity")
fi

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

run_ssh() {
  # Git Bash rewrites /tmp and /etc inside arguments passed to Windows ssh.
  # The assignment applies only to the ssh process, not to later tar/cp calls.
  if [ -n "$port" ] && [ -n "$identity" ]; then
    set -- -o ConnectTimeout=20 -p "$port" -i "$identity" "$@"
  elif [ -n "$port" ]; then
    set -- -o ConnectTimeout=20 -p "$port" "$@"
  elif [ -n "$identity" ]; then
    set -- -o ConnectTimeout=20 -i "$identity" "$@"
  else
    set -- -o ConnectTimeout=20 "$@"
  fi
  if [ -n "${MSYSTEM:-}" ]; then
    MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' command ssh "$@"
  else
    command ssh "$@"
  fi
}

install_binary_only() {
  remote=$(run_ssh "$target" 'd=$(mktemp -d /tmp/ship-rs-bootstrap.XXXXXX); printf "SHIP_DIR %s\n" "$d"' | awk '$1=="SHIP_DIR" { print $2 }')
  case "$remote" in
    /tmp/ship-rs-bootstrap.*) ;;
    *)
      echo "unexpected remote directory: $remote" >&2
      exit 1
      ;;
  esac

  echo "Uploading binary to $remote"
  if ! run_ssh "$target" "cat > '$remote/ship-rs'" < "$binary"; then
    echo "upload failed; the file remains on the server in $remote" >&2
    exit 1
  fi

  # The stage file is renamed onto ship-rs. trap stores that temporary path,
  # so a later failure cannot delete the installed binary.
  remote_script='set -eu
src=$1
regen=$2
dest=/usr/local/bin/ship-rs
stage=$(mktemp "$dest.XXXXXX")
trap "rm -f $stage" EXIT
install -m 0755 "$src" "$stage"
mv -f "$stage" "$dest"
trap - EXIT
systemctl restart ship-rs.service
n=0
while [ "$n" -lt 30 ]; do
  if curl -fsS http://127.0.0.1:8091/healthz >/dev/null; then
    break
  fi
  n=$((n + 1))
  sleep 0.2
done
curl -fsS http://127.0.0.1:8091/healthz
if [ "$regen" = 1 ]; then
  PATH="/usr/local/bin:$PATH"
  ship-rs generate --config /etc/ship-rs/sites.toml
  systemctl reload caddy
fi
'

  status=0
  if [ "$remote_uid" -eq 0 ]; then
    run_ssh "$target" "sh -c '$remote_script' sh '$remote/ship-rs' '$regen'" || status=$?
  else
    run_ssh -t "$target" "sudo sh -c '$remote_script' sh '$remote/ship-rs' '$regen'" || status=$?
  fi

  if [ "$status" -eq 0 ]; then
    run_ssh "$target" "rm -rf '$remote'"
    echo "Updated /usr/local/bin/ship-rs and restarted ship-rs.service."
    if [ "$regen" -eq 1 ]; then
      echo "Regenerated the Caddyfile and reloaded Caddy."
    fi
  else
    echo "binary update failed; the uploaded file remains on the server in $remote" >&2
    echo "/usr/local/bin/ship-rs may already be the new binary. sites.toml, ship-rs.env, site files, and the systemd unit were not changed." >&2
  fi
  exit "$status"
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
  if [ "$binary_only" -eq 1 ] && [ "$regen" -eq 1 ]; then
    printf 'Replace the ship-rs binary and regenerate the Caddyfile on %s? [y/N] ' "$target"
  elif [ "$binary_only" -eq 1 ]; then
    printf 'Replace the ship-rs binary on %s? [y/N] ' "$target"
  else
    printf 'Install ship-rs on %s? [y/N] ' "$target"
  fi
  read -r ans || exit 1
  case "$ans" in
    y|Y|yes|YES) ;;
    *)
      echo "cancelled"
      exit 1
      ;;
  esac
elif [ "${SHIP_YES:-}" != "1" ]; then
  if [ "$binary_only" -eq 1 ]; then
    echo "set SHIP_YES=1 to update the binary without a prompt" >&2
  else
    echo "set SHIP_YES=1 to install without a prompt" >&2
  fi
  exit 2
fi

if [ "$binary_only" -eq 1 ]; then
  install_binary_only
fi

remote=$(run_ssh "$target" 'd=$(mktemp -d /tmp/ship-rs-bootstrap.XXXXXX); printf "SHIP_DIR %s\n" "$d"' | awk '$1=="SHIP_DIR" { print $2 }')
case "$remote" in
  /tmp/ship-rs-bootstrap.*) ;;
  *)
    echo "unexpected remote directory: $remote" >&2
    exit 1
    ;;
esac

echo "Uploading binary and example sites to $remote"
stage=$(mktemp -d)
archive=$(mktemp)
trap 'rm -rf "$stage" "$archive"' EXIT
mkdir -p "$stage/prebuilt" "$stage/examples" "$stage/deploy" "$stage/scripts"
cp "$binary" "$stage/prebuilt/ship"
chmod 0755 "$stage/prebuilt/ship"
file_sha256 "$stage/prebuilt/ship" > "$stage/prebuilt/ship.sha256"
cp -a "$root/examples/public-hello" "$root/examples/protected-hello" "$root/examples/spa-demo" "$stage/examples/"
cp "$root/deploy/ship.service" "$root/deploy/ship.env.example" "$root/deploy/sites.arch.toml" "$stage/deploy/"
cp "$root/scripts/remote-bootstrap.sh" "$stage/scripts/"
tar -C "$stage" -czf "$archive" prebuilt examples deploy scripts
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
  echo "If pacman could not lock its database, wait until the other package manager finishes and run this script again." >&2
fi
exit "$status"
