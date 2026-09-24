#!/usr/bin/env bash
# Change the default / current passwords of the Wazuh stack to the values in .env.
#
#   ./scripts/change-passwords.sh indexer   # indexer 'admin' + 'kibanaserver'
#   ./scripts/change-passwords.sh api       # Wazuh API 'wazuh' + 'wazuh-wui'
#   ./scripts/change-passwords.sh all       # both (default)
#
# Rotation later on: edit the value(s) in .env and run this script again.
# If the 'wazuh' API password was changed outside this script, export
# CURRENT_API_ADMIN_PASSWORD=<current value> first.
source "$(dirname "$0")/lib.sh"
require docker; require curl; require python3

TARGET="${1:-all}"
[[ "$TARGET" =~ ^(indexer|api|all)$ ]] || die "usage: $0 [indexer|api|all]"

ctl validate
render_configs

running() { [[ -n "$(dc ps -q --status running "$1" 2>/dev/null)" ]]; }

change_indexer() {
  running wazuh.indexer || die "wazuh.indexer is not running (docker compose up -d first)"
  wait_for_indexer
  log "Applying internal_users.yml to the security index (securityadmin.sh)"
  local out
  out="$(dc exec -T wazuh.indexer bash -c '
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk
    D=/usr/share/wazuh-indexer
    bash $D/plugins/opensearch-security/tools/securityadmin.sh \
      -f $D/opensearch-security/internal_users.yml -t internalusers \
      -icl -nhnv -h localhost -p 9200 \
      -cacert $D/certs/root-ca.pem -cert $D/certs/admin.pem -key $D/certs/admin-key.pem' 2>&1)" || true
  grep -q 'Done with success' <<<"$out" || { echo "$out" >&2; die "securityadmin.sh failed"; }
  ok "security index updated"

  log "Recreating manager (Filebeat) and dashboard with the new credentials"
  dc up -d --force-recreate wazuh.manager wazuh.dashboard

  log "Verifying indexer logins"
  for pair in "admin:INDEXER_ADMIN_PASSWORD" "kibanaserver:DASHBOARD_KIBANASERVER_PASSWORD"; do
    user="${pair%%:*}"; pw="$(env_get "${pair#*:}")"
    # credentials are fed through stdin so they never show in `ps`
    code="$(printf 'user = "%s:%s"\n' "$user" "$pw" | curl -sk -K - -o /dev/null -w '%{http_code}' https://127.0.0.1:9200/)"
    [[ "$code" == "200" ]] && ok "indexer user '$user' OK" || die "indexer login for '$user' returned HTTP $code"
  done
  code="$(curl -sk -o /dev/null -w '%{http_code}' -u admin:SecretPassword https://127.0.0.1:9200/)"
  [[ "$code" == "401" ]] && ok "default admin:SecretPassword is rejected" || warn "default admin password check returned HTTP $code"
}

change_api() {
  running wazuh.manager || die "wazuh.manager is not running (docker compose up -d first)"
  wait_for_api
  log "Setting Wazuh API user passwords"
  ctl api-set-passwords
  log "Recreating manager + dashboard so env/wazuh.yml match the new API password"
  dc up -d --force-recreate wazuh.manager wazuh.dashboard
  wait_for_api
  code="$(curl -sk -o /dev/null -w '%{http_code}' -u wazuh:wazuh -X POST https://127.0.0.1:55000/security/user/authenticate)"
  [[ "$code" == "401" ]] && ok "default wazuh:wazuh is rejected" || warn "default API password check returned HTTP $code"
}

case "$TARGET" in
  indexer) change_indexer ;;
  api)     change_api ;;
  all)     change_indexer; change_api ;;
esac
ok "Password change complete. Dashboard login: admin / <INDEXER_ADMIN_PASSWORD from .env>"
