#!/usr/bin/env bash
# Enable password-protected (and optionally certificate-verified) agent enrollment.
#
# - writes ENROLLMENT_PASSWORD to /var/ossec/etc/authd.pass (root:wazuh 640)
# - installs the agent CA when AGENT_CERT_VERIFICATION=true
# - restarts the manager and checks that wazuh-authd picked the key up
#
# Rotate the key: change ENROLLMENT_PASSWORD in .env and rerun. Agents that
# are already enrolled keep working (they use their own client.keys).
source "$(dirname "$0")/lib.sh"
require docker; require python3

ctl validate
mkdir -p "$ROOT/secrets"; chmod 700 "$ROOT/secrets"
( umask 077; printf '%s\n' "$(env_get ENROLLMENT_PASSWORD)" > "$ROOT/secrets/authd.pass" )

log "Installing the enrollment key into the manager"
mgr bash -c 'install -o root -g wazuh -m 640 /opt/staging/secrets/authd.pass /var/ossec/etc/authd.pass'

if is_true AGENT_CERT_VERIFICATION; then
  [[ -f "$ROOT/config/agent_ssl_certs/rootCA.pem" ]] \
    || die "AGENT_CERT_VERIFICATION=true but no agent CA - run scripts/generate-agent-certs.sh --ca"
  log "Installing agent CA (ssl_agent_ca) into the manager"
  mgr bash -c 'install -d -o root -g wazuh -m 750 /var/ossec/etc/agent-ca &&
               install -o root -g wazuh -m 640 /opt/staging/agent_ssl_certs/rootCA.pem /var/ossec/etc/agent-ca/rootCA.pem'
fi

if [[ -f "$ROOT/config/agent_ssl_certs/manager/sslmanager.cert" ]]; then
  log "Installing CA-signed manager certificate (agents can verify the manager)"
  mgr bash -c 'install -o root -g wazuh -m 640 /opt/staging/agent_ssl_certs/manager/sslmanager.cert /var/ossec/etc/sslmanager.cert &&
               install -o root -g wazuh -m 640 /opt/staging/agent_ssl_certs/manager/sslmanager.key  /var/ossec/etc/sslmanager.key'
fi

log "Checking ossec.conf has <use_password>yes</use_password>"
mgr grep -q '<use_password>yes</use_password>' /var/ossec/etc/ossec.conf \
  || die "use_password is not enabled - re-render configs (scripts/setup.sh) and restart"

log "Restarting Wazuh manager"
mgr /var/ossec/bin/wazuh-control restart >/dev/null
sleep 10
if mgr bash -c 'tail -n 400 /var/ossec/logs/ossec.log | grep -q "authd.*Using password specified on file"'; then
  ok "wazuh-authd is enforcing the enrollment key (port 1515)"
else
  warn "Could not confirm from ossec.log; check: docker compose exec wazuh.manager grep authd /var/ossec/logs/ossec.log"
fi
