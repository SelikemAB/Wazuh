#!/usr/bin/env bash
# Install the custom MISP / TheHive integration scripts and the MISP rules into
# the running manager, then validate the configuration and restart it.
source "$(dirname "$0")/lib.sh"
require docker

log "Copying integration scripts to /var/ossec/integrations (root:wazuh 750)"
mgr bash -c '
  set -e
  for f in /opt/staging/integrations/custom-*; do
    install -o root -g wazuh -m 750 "$f" "/var/ossec/integrations/$(basename "$f")"
  done
  ls -l /var/ossec/integrations | grep custom-'

log "Copying custom rules to /var/ossec/etc/rules (wazuh:wazuh 660)"
mgr bash -c '
  set -e
  for f in /opt/staging/rules/*.xml; do
    install -o wazuh -g wazuh -m 660 "$f" "/var/ossec/etc/rules/$(basename "$f")"
  done'

log "Validating ruleset / configuration"
mgr /var/ossec/bin/wazuh-analysisd -t || die "wazuh-analysisd -t failed, see output above"

log "Restarting Wazuh manager"
mgr /var/ossec/bin/wazuh-control restart >/dev/null
sleep 5
mgr bash -c 'tail -n 200 /var/ossec/logs/ossec.log | grep -i integratord || true'
ok "Integrations installed. Watch /var/ossec/logs/integrations.log for activity."
