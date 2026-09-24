#!/usr/bin/env bash
# End-to-end first deployment:
#   host checks -> .env -> credential policy -> certs -> render configs ->
#   start stack -> change default API passwords -> enrollment key ->
#   integrations.
# Safe to re-run: every step is idempotent.
source "$(dirname "$0")/lib.sh"
require docker; require python3; require curl; require openssl
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 plugin is required"

# --- host prerequisites -----------------------------------------------------
if [[ "$(uname -s)" == "Linux" ]]; then
  current="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
  if (( current < 262144 )); then
    warn "vm.max_map_count=$current (indexer/Elasticsearch need >= 262144)"
    warn "fix: sudo sysctl -w vm.max_map_count=262144 && echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf"
    die "host prerequisite missing"
  fi
fi

# --- configuration ----------------------------------------------------------
[[ -f "$ROOT/.env" ]] || "$ROOT/scripts/init-env.sh"
ctl validate
mkdir -p "$ROOT/secrets" "$ROOT/config/agent_ssl_certs"; chmod 700 "$ROOT/secrets"
( umask 077; printf '%s\n' "$(env_get ENROLLMENT_PASSWORD)" > "$ROOT/secrets/authd.pass" )
"$ROOT/scripts/generate-certs.sh"
conf="$ROOT/config/wazuh_cluster/wazuh_manager.conf"
before="$(cat "$conf" "$ROOT/config/wazuh_dashboard/wazuh.yml" 2>/dev/null | sha256sum)"
render_configs
after="$(cat "$conf" "$ROOT/config/wazuh_dashboard/wazuh.yml" | sha256sum)"

# --- start ------------------------------------------------------------------
log "Starting the stack"
already_running="$(dc ps -q --status running wazuh.manager 2>/dev/null || true)"
dc up -d
if [[ -n "$already_running" && "$before" != "$after" ]]; then
  # ossec.conf / wazuh.yml are copied in at container start: restart to apply.
  log "Configuration changed - restarting manager and dashboard"
  dc restart wazuh.manager wazuh.dashboard
fi
wait_for_api

# --- hardening --------------------------------------------------------------
# Indexer users were created from our hashes on first boot of the security
# index; the API 'wazuh' user still has the factory default until now.
log "Replacing default Wazuh API passwords"
ctl api-set-passwords
"$ROOT/scripts/enable-enrollment.sh"
"$ROOT/scripts/install-integrations.sh"
if is_true ENABLE_SHUFFLE_STACK; then
  "$ROOT/scripts/shuffle-setup.sh"
fi

ok "Deployment complete"
cat <<MSG

  Dashboard : https://<this-host>:$(env_get DASHBOARD_PORT)   (user: admin, password: INDEXER_ADMIN_PASSWORD in .env)
  API       : https://<this-host>:55000                (user: wazuh, password: API_ADMIN_PASSWORD in .env)
  Enrollment: TCP 1515, key = ENROLLMENT_PASSWORD in .env   -> docs/02-agent-enrollment.md

  If the indexer volume existed BEFORE this run (e.g. an earlier deployment with
  default passwords), also run: ./scripts/change-passwords.sh indexer
MSG
