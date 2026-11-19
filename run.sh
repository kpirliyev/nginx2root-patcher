#!/usr/bin/env bash
# nginx2root-patcher: check nginx versions across your servers and update them
# from each server's own package repositories.
set -euo pipefail
cd "$(dirname "$0")"

usage() {
  cat <<'EOF'
Usage:
  ./run.sh check  [options]     Report nginx version and patch status (read-only)
  ./run.sh update [options]     Upgrade nginx where the host's repos offer a newer
                                package, then restart it

Options for both:
  -i, --inventory FILE   Inventory file (default: inventory.ini)
  -l, --limit PATTERN    Only these hosts or groups, e.g. -l web1 or -l 'web*'
      --local            Run against this machine instead of an inventory
      --no-refresh       Do not refresh package metadata (apt-get update etc.)
  -h, --help             Show this help

Options for check:
      --strict           Exit non-zero if any host is unpatched or needs a restart

Options for update:
      --dry-run          Show what would be done, change nothing
      --serial N         Update N hosts at a time (also accepts 25%)
      --no-restart       Upgrade the package but do not restart nginx
  -y, --yes              Do not ask for confirmation

Anything else is passed to ansible-playbook, for example:
  -u USER   remote user          -k   ask for the SSH password
  -K        ask for the sudo password      -v   show package manager output

Examples:
  ./run.sh check
  ./run.sh check -l web1 -K
  ./run.sh update --dry-run
  ./run.sh update --serial 1
  sudo ./run.sh check --local
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

CMD=${1:-help}
[ $# -gt 0 ] && shift

case "$CMD" in
  check | update) ;;
  help | -h | --help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    die "unknown command: $CMD"
    ;;
esac

INVENTORY=inventory.ini
LOCAL=0
YES=0
DRY=0
ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    -i | --inventory)
      [ $# -ge 2 ] || die "$1 needs a file name"
      INVENTORY=$2
      shift 2
      ;;
    --local)
      LOCAL=1
      shift
      ;;
    --no-refresh)
      ARGS+=(-e refresh_cache=false)
      shift
      ;;
    --strict)
      ARGS+=(-e fail_on_vulnerable=true)
      shift
      ;;
    --dry-run)
      DRY=1
      ARGS+=(-e dry_run=true)
      shift
      ;;
    --no-restart)
      ARGS+=(-e restart=false)
      shift
      ;;
    --serial)
      [ $# -ge 2 ] || die "--serial needs a number or a percentage"
      ARGS+=(-e "nginx_serial=$2")
      shift 2
      ;;
    -y | --yes)
      YES=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      ARGS+=("$1")
      shift
      ;;
  esac
done

if ! command -v ansible-playbook >/dev/null 2>&1; then
  cat >&2 <<'EOF'
error: ansible-playbook was not found on this machine.

Install Ansible on the machine you run this from (not on the servers):
  macOS:          brew install ansible
  Debian/Ubuntu:  sudo apt install ansible
  Fedora/RHEL:    sudo dnf install ansible-core
  anywhere:       pipx install ansible-core
EOF
  exit 1
fi

if [ "$LOCAL" = 1 ]; then
  TARGET=(-i "localhost," -c local)
else
  if [ ! -f "$INVENTORY" ]; then
    cat >&2 <<EOF
error: inventory file '$INVENTORY' not found.

Create one from the example and list your servers in it:
  cp inventory.example.ini inventory.ini
  \$EDITOR inventory.ini

Or run against this machine only:  sudo ./run.sh $CMD --local
EOF
    exit 1
  fi
  TARGET=(-i "$INVENTORY")
fi

if [ "$CMD" = update ] && [ "$DRY" = 0 ] && [ "$YES" = 0 ]; then
  echo "This will upgrade nginx from each host's own repositories and RESTART it."
  echo "Hosts with no newer package are left untouched. Preview with: ./run.sh update --dry-run"
  if [ ! -t 0 ]; then
    die "not a terminal; pass --yes to confirm"
  fi
  read -r -p "Type 'yes' to continue: " answer
  [ "$answer" = yes ] || die "aborted"
fi

exec ansible-playbook "${TARGET[@]}" "$CMD.yml" ${ARGS[@]+"${ARGS[@]}"}
