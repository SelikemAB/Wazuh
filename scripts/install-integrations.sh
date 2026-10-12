#!/usr/bin/env bash
# Install the custom MISP / TheHive integration scripts and everything under
# custom/rules and custom/decoders into the running manager, validate the
# ruleset (rolling back on failure) and restart the manager.
source "$(dirname "$0")/lib.sh"
require docker

log "Copying integration scripts to /var/ossec/integrations (root:wazuh 750)"
mgr bash -c '
  set -e
  for f in /opt/staging/integrations/custom-*; do
    install -o root -g wazuh -m 750 "$f" "/var/ossec/integrations/$(basename "$f")"
  done
  ls -l /var/ossec/integrations | grep custom-'

log "Installing custom rules and decoders (custom/ -> /var/ossec/etc, wazuh:wazuh 660)"
# Files are backed up before being replaced; if wazuh-analysisd -t rejects the
# result, every change is rolled back so a broken file never stays installed.
mgr bash -c '
  set -e
  shopt -s nullglob
  backup=$(mktemp -d)
  installed=()
  for kind in rules decoders; do
    for f in /opt/staging/$kind/*.xml; do
      dst="/var/ossec/etc/$kind/$(basename "$f")"
      [ -e "$dst" ] && cp -p "$dst" "$backup/$kind--$(basename "$f")"
      install -o wazuh -g wazuh -m 660 "$f" "$dst"
      installed+=("$dst")
      echo "  $dst"
    done
  done
  if /var/ossec/bin/wazuh-analysisd -t; then
    rm -rf "$backup"
    exit 0
  fi
  echo "wazuh-analysisd -t failed - rolling back" >&2
  for dst in "${installed[@]}"; do
    kind=$(basename "$(dirname "$dst")")
    saved="$backup/$kind--$(basename "$dst")"
    if [ -e "$saved" ]; then cp -p "$saved" "$dst"; else rm -f "$dst"; fi
  done
  rm -rf "$backup"
  exit 1' || die "custom rules/decoders rejected by wazuh-analysisd -t (rolled back, see output above)"

log "Restarting Wazuh manager"
mgr /var/ossec/bin/wazuh-control restart >/dev/null
sleep 5
mgr bash -c 'tail -n 200 /var/ossec/logs/ossec.log | grep -i integratord || true'
ok "Integrations installed. Watch /var/ossec/logs/integrations.log for activity."
