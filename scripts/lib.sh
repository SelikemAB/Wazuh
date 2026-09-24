#!/usr/bin/env bash
# Shared helpers for the deployment scripts. Source it, don't run it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed"; }

ctl()     { python3 "$ROOT/scripts/wazuhctl.py" "$@"; }
env_get() { ctl get "$1"; }
is_true() { [[ "$(env_get "$1" | tr '[:upper:]' '[:lower:]')" =~ ^(1|true|yes|on)$ ]]; }

# docker compose with the SOAR overlay added when ENABLE_SOAR_STACK=true
dc() {
  local files=(-f "$ROOT/docker-compose.yml")
  if is_true ENABLE_SOAR_STACK; then files+=(-f "$ROOT/docker-compose.soar.yml"); fi
  docker compose --env-file "$ROOT/.env" "${files[@]}" "$@"
}

# Run a command inside the manager container
mgr() { dc exec -T wazuh.manager "$@"; }

# bcrypt-hash a password with the indexer's own hash.sh. The password is
# passed through the environment so it never appears in `ps` output.
indexer_hash() {
  local version; version="$(env_get WAZUH_VERSION)"
  PW="$1" docker run --rm -e PW --entrypoint /bin/bash "wazuh/wazuh-indexer:${version}" -c \
    'export JAVA_HOME=/usr/share/wazuh-indexer/jdk;
     bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$PW"' \
    2>/dev/null | grep -E '^\$2[aby]\$' | tail -n1
}

render_configs() {
  log "Hashing indexer passwords (bcrypt, via wazuh-indexer image)"
  local admin_hash kibana_hash
  admin_hash="$(indexer_hash "$(env_get INDEXER_ADMIN_PASSWORD)")"
  kibana_hash="$(indexer_hash "$(env_get DASHBOARD_KIBANASERVER_PASSWORD)")"
  [[ -n "$admin_hash" && -n "$kibana_hash" ]] || die "password hashing failed"
  log "Rendering configuration templates"
  INDEXER_ADMIN_HASH="$admin_hash" DASHBOARD_KIBANASERVER_HASH="$kibana_hash" ctl render
}

wait_for_api() {
  log "Waiting for the Wazuh API on https://127.0.0.1:55000 ..."
  for _ in $(seq 1 60); do
    if curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:55000/ | grep -qE '^(200|401)$'; then
      ok "Wazuh API is up"; return 0
    fi
    sleep 5
  done
  die "Wazuh API did not come up in 5 minutes (docker compose logs wazuh.manager)"
}

wait_for_indexer() {
  log "Waiting for the Wazuh indexer ..."
  for _ in $(seq 1 60); do
    if dc exec -T wazuh.indexer curl -sk -o /dev/null -w '%{http_code}' https://localhost:9200 2>/dev/null | grep -qE '^(200|401)$'; then
      ok "Wazuh indexer is up"; return 0
    fi
    sleep 5
  done
  die "Wazuh indexer did not come up in 5 minutes"
}
