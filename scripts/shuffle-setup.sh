#!/usr/bin/env bash
# Bring up Shuffle and wire it to Wazuh:
#   1. start the Shuffle containers (docker-compose.shuffle.yml)
#   2. create the least-privilege Wazuh API user for active response
#   3. build + import the starter workflows and start their webhooks
#   4. write the webhook URLs into .env, render ossec.conf, restart the manager
# Idempotent: re-run after changing any SHUFFLE_* value in .env.
source "$(dirname "$0")/lib.sh"
require docker; require python3; require curl

is_true ENABLE_SHUFFLE_STACK || die "set ENABLE_SHUFFLE_STACK=true (and SOAR_HOST_ADDRESS) in .env first"
[[ -n "$(env_get SOAR_HOST_ADDRESS)" ]] || die "SOAR_HOST_ADDRESS is empty - set it to this host's LAN IP (e.g. $(hostname -I 2>/dev/null | awk '{print $1}'))"
if [[ "$(env_get API_BIND)" == "127.0.0.1" ]]; then
  warn "API_BIND=127.0.0.1: Shuffle apps cannot reach the Wazuh API at $(env_get SOAR_HOST_ADDRESS):55000,"
  warn "so the auto-response workflow will fail. Set API_BIND to the host IP (firewall it) or 0.0.0.0."
fi
# Validate everything except the webhook URLs, which this script produces.
if [[ -z "$(env_get SHUFFLE_WEBHOOK_URLS)" ]]; then
  sed -i 's/^ENABLE_SHUFFLE=.*/ENABLE_SHUFFLE=false/' "$ROOT/.env"
fi
ctl validate

log "Starting Shuffle containers"
dc up -d shuffle-opensearch shuffle-backend shuffle-frontend shuffle-orborus

log "Waiting for the Shuffle backend (first start downloads apps, can take minutes) ..."
key="$(env_get SHUFFLE_ADMIN_APIKEY)"
for i in $(seq 1 90); do
  code="$(printf 'header = "Authorization: Bearer %s"\n' "$key" | \
          curl -s -K - -o /dev/null -w '%{http_code}' http://127.0.0.1:5001/api/v1/workflows || true)"
  [[ "$code" == "200" ]] && break
  (( i == 90 )) && die "Shuffle backend not ready (docker compose logs shuffle-backend)"
  sleep 10
done
ok "Shuffle backend is up"

if [[ -n "$(dc ps -q --status running wazuh.manager 2>/dev/null || true)" ]]; then
  wait_for_api
  log "Creating least-privilege Wazuh API user for Shuffle"
  ctl api-create-shuffle-user
else
  warn "wazuh.manager is not running - skipping API user creation (run scripts/setup.sh first)"
fi

log "Building and importing starter workflows"
python3 "$ROOT/scripts/shuffle_workflows.py" import --write-env

log "Rendering ossec.conf with the Shuffle integration and restarting the manager"
ctl validate
render_configs
dc restart wazuh.manager
wait_for_api

ok "Shuffle is wired to Wazuh"
cat <<MSG

  Shuffle UI : https://$(env_get SOAR_HOST_ADDRESS):$(env_get SHUFFLE_PORT)
  Login      : $(env_get SHUFFLE_ADMIN_USERNAME) / SHUFFLE_ADMIN_PASSWORD in .env
  Workflows  : Wazuh - Enrich & TheHive case | Wazuh - Auto-response (block IP) | Wazuh - Notification
  Next       : open each workflow, check its variables (keys for MISP/TheHive/Cortex,
               Slack/Teams/SMTP) and that the Webhook node shows as running.
               docs/05-shuffle.md
MSG
