#!/bin/sh
# nginx-host.sh - runs ON a target host. POSIX sh, no Python required.
#
#   nginx-host.sh check  [--no-refresh]
#   nginx-host.sh update [--no-refresh] [--no-restart] [--dry-run]
#
# Progress goes to stderr. Exactly one machine-readable line goes to stdout:
#   N2R_JSON={...}
# The Ansible playbooks in this repository parse that line. You can also run
# this script by hand as root on a single server.

set -u
LC_ALL=C
export LC_ALL
PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin"
export PATH

# First upstream releases that contain the nginx2root fixes.
FIXED_STABLE_MINOR=30
FIXED_STABLE_PATCH=7
FIXED_MAINLINE_MINOR=31
FIXED_MAINLINE_PATCH=9
CVE_REGEX='CVE-2026-(123007|123633|123634|121810|113425)'
LEAD_CVE='CVE-2026-123007'

MODE=${1:-check}
[ $# -gt 0 ] && shift
REFRESH=1
RESTART=1
DRYRUN=0
for arg in "$@"; do
  case "$arg" in
    --no-refresh) REFRESH=0 ;;
    --no-restart) RESTART=0 ;;
    --dry-run) DRYRUN=1 ;;
    "") ;;
    *) printf 'unknown option: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

log() { printf '[nginx2root] %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- output ----

CHANGED=false
ACTION=none
MESSAGE=""
ERROR=""
VERSION_BEFORE=""

js() { printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'; }
kv() { printf '"%s":"%s",' "$1" "$(js "$2")"; }

emit() {
  printf 'N2R_JSON={'
  kv mode "$MODE"
  kv distro "$DISTRO"
  kv installed "$INSTALLED"
  kv flavor "$FLAVOR"
  kv binary "$BIN"
  kv version "$VERSION"
  kv running "$RUNNING"
  kv running_version "$RUN_VERSION"
  kv restart_needed "$RESTART_NEEDED"
  kv pkg_manager "$PKG_MGR"
  kv packages "$PACKAGES"
  kv update "$UPDATE"
  kv candidate "$CANDIDATE"
  kv status "$STATUS"
  kv cves_in_changelog "$CVES_FOUND"
  kv http2 "$HTTP2"
  kv http3 "$HTTP3"
  kv sctp "$SCTP"
  kv container_nginx "$CONTAINER_COUNT"
  kv version_before "$VERSION_BEFORE"
  kv action "$ACTION"
  kv message "$MESSAGE"
  kv error "$ERROR"
  printf '"changed":%s}\n' "$CHANGED"
}

die() {
  ERROR=$1
  log "ERROR: $ERROR"
  emit
  exit 1
}

# ----------------------------------------------------------------- probe ----

DISTRO=$( (. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-${NAME:-unknown}}") || true)
[ -n "$DISTRO" ] || DISTRO=unknown

parse_version() {
  printf '%s\n' "$1" | sed -n 's#^.*version: *[^/]*/\([0-9][0-9.]*\).*$#\1#p' | head -n 1
}

parse_flavor() {
  case "$1" in
    *nginx-plus*) printf 'nginx-plus'; return ;;
  esac
  printf '%s\n' "$1" | sed -n 's#^.*version: *\([^/]*\)/.*$#\1#p' | head -n 1 | tr 'A-Z' 'a-z'
}

find_binary() {
  BIN=""
  for c in nginx openresty angie tengine; do
    if have "$c"; then
      BIN=$(command -v "$c")
      return
    fi
  done
  for c in /usr/sbin/nginx /usr/local/sbin/nginx /usr/local/nginx/sbin/nginx \
           /opt/nginx/sbin/nginx /usr/local/openresty/nginx/sbin/nginx; do
    if [ -x "$c" ]; then
      BIN=$c
      return
    fi
  done
}

# Finds nginx master processes. Masters that live in another mount namespace
# (containers) are only counted: they have to be fixed by rebuilding the image.
scan_processes() {
  RUN_PID=""
  CONTAINER_COUNT=0
  selfns=$(readlink /proc/self/ns/mnt 2>/dev/null || true)
  for d in /proc/[0-9]*; do
    [ -r "$d/cmdline" ] || continue
    cmd=$(tr '\000' ' ' <"$d/cmdline" 2>/dev/null) || continue
    case "$cmd" in
      "nginx: master process"*) ;;
      *) continue ;;
    esac
    ns=$(readlink "$d/ns/mnt" 2>/dev/null || true)
    if [ -n "$selfns" ] && [ -n "$ns" ] && [ "$ns" != "$selfns" ]; then
      CONTAINER_COUNT=$((CONTAINER_COUNT + 1))
      continue
    fi
    [ -n "$RUN_PID" ] || RUN_PID=${d#/proc/}
  done
}

detect_packages() {
  PKG_MGR=none
  PACKAGES=""
  PKG_NAMES=""
  pat=nginx
  case "$FLAVOR" in
    openresty | angie) pat=$FLAVOR ;;
  esac

  if have dpkg-query; then
    PACKAGES=$(dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Version}\n' \
      "${pat}*" "lib${pat}-mod*" 2>/dev/null |
      awk -F'|' '$1 ~ /^ii/ {printf "%s=%s ", $2, $3}')
    [ -n "$PACKAGES" ] && PKG_MGR=apt
  fi
  if [ "$PKG_MGR" = none ] && have rpm; then
    PACKAGES=$(rpm -qa --qf '%{NAME}=%{VERSION}-%{RELEASE} ' "${pat}*" 2>/dev/null)
    if [ -n "$PACKAGES" ]; then
      if have zypper; then
        PKG_MGR=zypper
      elif have dnf; then
        PKG_MGR=dnf
      elif have yum; then
        PKG_MGR=yum
      else
        PKG_MGR=rpm
      fi
    fi
  fi
  if [ "$PKG_MGR" = none ] && have apk; then
    PKG_NAMES=$(apk info 2>/dev/null | grep "^${pat}" | tr '\n' ' ')
    if [ -n "$PKG_NAMES" ]; then
      PKG_MGR=apk
      PACKAGES=$(apk info -v 2>/dev/null | grep "^${pat}" | tr '\n' ' ')
    fi
  fi
  if [ "$PKG_MGR" = none ] && have pacman; then
    PACKAGES=$(pacman -Q 2>/dev/null | awk -v p="^${pat}" '$1 ~ p {printf "%s=%s ", $1, $2}')
    [ -n "$PACKAGES" ] && PKG_MGR=pacman
  fi
  if [ "$PKG_MGR" != none ] && [ "$PKG_MGR" != apk ]; then
    PKG_NAMES=$(printf '%s' "$PACKAGES" | tr ' ' '\n' | sed 's/=.*//' | tr '\n' ' ')
  fi
  PACKAGES=${PACKAGES% }
}

# Sets UPDATE=yes|no|unknown and CANDIDATE from the repositories that are
# already configured on the host. Never adds or changes repositories.
check_update() {
  UPDATE=unknown
  CANDIDATE=""
  case "$PKG_MGR" in
    apt)
      if [ "$REFRESH" = 1 ]; then
        apt-get update -qq >&2 || log "warning: apt-get update failed, using cached package lists"
      fi
      UPDATE=no
      for p in $PKG_NAMES; do
        pol=$(apt-cache policy "$p" 2>/dev/null)
        inst=$(printf '%s\n' "$pol" | awk '/^ +Installed:/ {print $2; exit}')
        cand=$(printf '%s\n' "$pol" | awk '/^ +Candidate:/ {print $2; exit}')
        [ -n "$cand" ] && [ "$cand" != "(none)" ] || continue
        if dpkg --compare-versions "$cand" gt "$inst" 2>/dev/null; then
          UPDATE=yes
          [ -n "$CANDIDATE" ] || CANDIDATE=$cand
        fi
      done
      ;;
    dnf | yum)
      if [ "$REFRESH" = 1 ]; then
        "$PKG_MGR" -q clean expire-cache >/dev/null 2>&1 || true
      fi
      # shellcheck disable=SC2086
      out=$("$PKG_MGR" -q check-update $PKG_NAMES 2>/dev/null)
      rc=$?
      case "$rc" in
        100)
          UPDATE=yes
          CANDIDATE=$(printf '%s\n' "$out" | awk 'NF >= 3 {print $2; exit}')
          ;;
        0) UPDATE=no ;;
        *) log "warning: $PKG_MGR check-update failed (exit $rc)" ;;
      esac
      ;;
    zypper)
      if [ "$REFRESH" = 1 ]; then
        zypper -n -q refresh >&2 || log "warning: zypper refresh failed"
      fi
      out=$(zypper -n list-updates 2>/dev/null) || {
        log "warning: zypper list-updates failed"
        return
      }
      UPDATE=no
      for p in $PKG_NAMES; do
        cand=$(printf '%s\n' "$out" | awk -F'|' -v p="$p" \
          'NF >= 5 {gsub(/ /, "", $3); gsub(/ /, "", $5); if ($3 == p) {print $5; exit}}')
        if [ -n "$cand" ]; then
          UPDATE=yes
          [ -n "$CANDIDATE" ] || CANDIDATE=$cand
        fi
      done
      ;;
    apk)
      if [ "$REFRESH" = 1 ]; then
        apk update >&2 || log "warning: apk update failed"
      fi
      UPDATE=no
      cand=$(apk version 2>/dev/null | awk '$1 ~ /^(nginx|openresty|angie)/ && $2 == "<" {print $3; exit}')
      if [ -n "$cand" ]; then
        UPDATE=yes
        CANDIDATE=$cand
      fi
      ;;
    pacman)
      # No database refresh here: "pacman -Sy" without a full upgrade is unsafe.
      UPDATE=no
      cand=$({ have checkupdates && checkupdates 2>/dev/null || pacman -Qu 2>/dev/null; } |
        awk '$1 ~ /^nginx/ {print $NF; exit}')
      if [ -n "$cand" ]; then
        UPDATE=yes
        CANDIDATE=$cand
      fi
      ;;
  esac
}

changelog_text() {
  case "$PKG_MGR" in
    apt)
      for f in /usr/share/doc/nginx*/changelog.Debian.gz /usr/share/doc/nginx*/changelog.gz \
               /usr/share/doc/libnginx*/changelog.Debian.gz; do
        [ -f "$f" ] && gzip -dc "$f" 2>/dev/null
      done
      ;;
    dnf | yum | zypper | rpm)
      # shellcheck disable=SC2086
      rpm -q --changelog $PKG_NAMES 2>/dev/null
      ;;
  esac
}

# Sets STATUS:
#   fixed          upstream version already contains the fixes
#   fixed-backport older version string, but the package changelog lists the fix
#   vulnerable     no fix found
#   unverified     old version string and no changelog to prove a backport
#   check-vendor   NGINX Plus or an nginx fork with its own version numbers
assess() {
  CVES_FOUND=""
  case "$FLAVOR" in
    nginx) ;;
    *)
      STATUS=check-vendor
      return
      ;;
  esac
  # shellcheck disable=SC2046
  set -- $(printf '%s' "$VERSION" | tr '.' ' ')
  vmaj=${1:-}
  vmin=${2:-0}
  vpat=${3:-0}
  case "$vmaj$vmin$vpat" in
    "" | *[!0-9]*)
      STATUS=unverified
      return
      ;;
  esac
  if [ "$vmaj" -gt 1 ] ||
     { [ "$vmaj" -eq 1 ] && [ "$vmin" -gt "$FIXED_MAINLINE_MINOR" ]; } ||
     { [ "$vmaj" -eq 1 ] && [ "$vmin" -eq "$FIXED_MAINLINE_MINOR" ] && [ "$vpat" -ge "$FIXED_MAINLINE_PATCH" ]; } ||
     { [ "$vmaj" -eq 1 ] && [ "$vmin" -eq "$FIXED_STABLE_MINOR" ] && [ "$vpat" -ge "$FIXED_STABLE_PATCH" ]; }; then
    STATUS=fixed
    return
  fi
  has_changelog=$(changelog_text | head -c 1 | wc -c | tr -d ' ')
  if [ "$has_changelog" = 0 ]; then
    # A build that does not come from a package has no backports: the version
    # string is the truth. A package without a changelog cannot be judged.
    if [ "$PKG_MGR" = none ]; then
      STATUS=vulnerable
    else
      STATUS=unverified
    fi
    return
  fi
  CVES_FOUND=$(changelog_text | grep -oE "$CVE_REGEX" | sort -u | tr '\n' ' ')
  CVES_FOUND=${CVES_FOUND% }
  case " $CVES_FOUND " in
    *" $LEAD_CVE "*) STATUS=fixed-backport ;;
    *) STATUS=vulnerable ;;
  esac
}

detect_protocols() {
  HTTP2=unknown
  HTTP3=unknown
  conf=$("$BIN" -T 2>/dev/null | sed 's/#.*//') || true
  [ -n "$conf" ] || return 0
  if printf '%s\n' "$conf" | grep -Eq 'listen[^;]*[[:space:]]http2|http2[[:space:]]+on'; then
    HTTP2=on
  else
    HTTP2=off
  fi
  if printf '%s\n' "$conf" | grep -Eq 'listen[^;]*[[:space:]]quic|http3[[:space:]]+on'; then
    HTTP3=on
  else
    HTTP3=off
  fi
}

detect_sctp() {
  if [ -d /sys/module/sctp ]; then
    SCTP=loaded
  elif grep -rqsE '^[[:space:]]*install[[:space:]]+sctp[[:space:]]+/bin/(false|true)' \
    /etc/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null; then
    SCTP=blocked
  elif have modinfo && modinfo sctp >/dev/null 2>&1; then
    SCTP=loadable
  elif have modinfo; then
    SCTP=absent
  else
    SCTP=unknown
  fi
}

probe() {
  INSTALLED=no
  FLAVOR=""
  VERSION=""
  RUNNING=no
  RUN_VERSION=""
  RESTART_NEEDED=no
  UPDATE=unknown
  CANDIDATE=""
  STATUS=not-installed
  CVES_FOUND=""
  HTTP2=unknown
  HTTP3=unknown
  PKG_MGR=none
  PACKAGES=""
  PKG_NAMES=""

  find_binary
  scan_processes

  if [ -n "$RUN_PID" ]; then
    RUNNING=yes
    exe=$(readlink "/proc/$RUN_PID/exe" 2>/dev/null || true)
    run_raw=$("/proc/$RUN_PID/exe" -v 2>&1 || true)
    RUN_VERSION=$(parse_version "$run_raw")
    case "$exe" in
      *" (deleted)") RESTART_NEEDED=yes ;;
    esac
    if [ -z "$BIN" ] && [ -n "$exe" ]; then
      BIN=${exe% (deleted)}
      [ -x "$BIN" ] || BIN="/proc/$RUN_PID/exe"
    fi
  fi

  if [ -n "$BIN" ]; then
    INSTALLED=yes
    raw=$("$BIN" -v 2>&1 || true)
    VERSION=$(parse_version "$raw")
    FLAVOR=$(parse_flavor "$raw")
    if [ -n "$RUN_VERSION" ] && [ -n "$VERSION" ] && [ "$RUN_VERSION" != "$VERSION" ]; then
      RESTART_NEEDED=yes
    fi
    detect_packages
    check_update
    assess
    detect_protocols
  fi
  detect_sctp
}

# ---------------------------------------------------------------- update ----

do_upgrade() {
  case "$PKG_MGR" in
    apt)
      # shellcheck disable=SC2086
      DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get install -y --only-upgrade \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
        $PKG_NAMES >&2
      ;;
    dnf)
      # shellcheck disable=SC2086
      dnf -y upgrade $PKG_NAMES >&2
      ;;
    yum)
      # shellcheck disable=SC2086
      yum -y update $PKG_NAMES >&2
      ;;
    zypper)
      # shellcheck disable=SC2086
      zypper -n update $PKG_NAMES >&2
      ;;
    apk)
      # shellcheck disable=SC2086
      apk upgrade $PKG_NAMES >&2
      ;;
    *) return 2 ;;
  esac
}

do_restart() {
  svc=nginx
  case "$FLAVOR" in
    openresty | angie) svc=$FLAVOR ;;
  esac
  if have systemctl && [ -d /run/systemd/system ]; then
    systemctl restart "$svc" >&2
  elif have rc-service; then
    rc-service "$svc" restart >&2
  elif have service; then
    service "$svc" restart >&2
  else
    "$BIN" -s stop >&2 || true
    sleep 2
    "$BIN" >&2
  fi
}

wait_for_master() {
  i=0
  while [ "$i" -lt 15 ]; do
    scan_processes
    if [ -n "$RUN_PID" ]; then
      exe=$(readlink "/proc/$RUN_PID/exe" 2>/dev/null || true)
      case "$exe" in
        *" (deleted)") ;;
        *) return 0 ;;
      esac
    fi
    sleep 1
    i=$((i + 1))
  done
  return 1
}

run_update() {
  [ "$(id -u)" = 0 ] || die "update needs root (use become/sudo)"

  if [ "$INSTALLED" != yes ]; then
    MESSAGE="nginx is not installed on this host"
    return
  fi

  need_upgrade=no
  [ "$UPDATE" = yes ] && need_upgrade=yes
  need_restart=no
  [ "$RESTART_NEEDED" = yes ] && [ "$RESTART" = 1 ] && need_restart=yes

  if [ "$need_upgrade" = yes ]; then
    case "$PKG_MGR" in
      pacman)
        die "Arch Linux does not support upgrading a single package. Run 'pacman -Syu' on this host, then restart nginx."
        ;;
    esac
  fi

  if [ "$need_upgrade" = no ] && [ "$need_restart" = no ]; then
    case "$PKG_MGR" in
      none | rpm)
        MESSAGE="nginx $VERSION was not installed through a supported package manager; upgrade it manually"
        ;;
      *)
        if [ "$UPDATE" = unknown ]; then
          MESSAGE="could not query the repositories of this host; nothing changed"
        elif [ "$RESTART_NEEDED" = yes ]; then
          MESSAGE="no newer package in the configured repos, but the running process is older than the installed binary; restart pending (--no-restart)"
        else
          MESSAGE="no newer nginx package in the configured repos (installed: $VERSION, status: $STATUS)"
        fi
        ;;
    esac
    return
  fi

  VERSION_BEFORE=$VERSION
  pkg_before=${PACKAGES%% *}
  was_running=$RUNNING

  if [ "$DRYRUN" = 1 ]; then
    if [ "$need_upgrade" = yes ]; then
      ACTION=would-upgrade
      MESSAGE="would upgrade nginx $VERSION to package version $CANDIDATE"
      if [ "$RESTART" = 1 ] && [ "$was_running" = yes ]; then
        MESSAGE="$MESSAGE and restart it"
      fi
    else
      ACTION=would-restart
      MESSAGE="would restart nginx: the running process is older than the installed binary"
    fi
    return
  fi

  log "testing the current configuration"
  "$BIN" -t >&2 2>&1 ||
    die "'nginx -t' fails with the CURRENT configuration. Nothing was changed. Fix the configuration first."

  if [ "$need_upgrade" = yes ]; then
    log "upgrading: $PKG_NAMES"
    do_upgrade || die "the package upgrade failed; see the output above. nginx was not restarted."
    CHANGED=true
    ACTION=upgraded
    find_binary
    log "testing the configuration with the new binary"
    "$BIN" -t >&2 2>&1 ||
      die "the package was upgraded, but the new binary rejects the configuration. nginx was NOT restarted and the old process is still serving. Fix the configuration, then restart nginx."
  fi

  if [ "$RESTART" = 1 ] && [ "$was_running" = yes ]; then
    log "restarting nginx"
    do_restart || die "the restart command failed. Check the service on this host NOW."
    wait_for_master || die "nginx did not come back after the restart. Check the service on this host NOW."
    CHANGED=true
    if [ "$ACTION" = upgraded ]; then
      ACTION=upgraded+restarted
    else
      ACTION=restarted
    fi
  fi

  REFRESH=0
  probe
  pkg_after=${PACKAGES%% *}
  what="upgraded $pkg_before -> ${pkg_after#*=}"

  case "$ACTION" in
    upgraded+restarted) MESSAGE="$what and restarted nginx" ;;
    restarted) MESSAGE="restarted nginx so the installed binary ($VERSION) is the one running" ;;
    upgraded)
      if [ "$was_running" = yes ]; then
        MESSAGE="$what; restart skipped (--no-restart), the OLD binary is still running"
      else
        MESSAGE="$what; nginx was not running before, so it was left stopped"
      fi
      ;;
  esac
  MESSAGE="$MESSAGE (status: $STATUS)"
}

# ------------------------------------------------------------------ main ----

case "$MODE" in
  check)
    [ "$(id -u)" = 0 ] || log "warning: not running as root, some checks will be incomplete"
    probe
    emit
    ;;
  update)
    probe
    run_update
    emit
    ;;
  *)
    printf 'usage: %s check|update [--no-refresh] [--no-restart] [--dry-run]\n' "$0" >&2
    exit 2
    ;;
esac
