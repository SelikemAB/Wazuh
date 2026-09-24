#!/usr/bin/env bash
# Optional second enrollment factor: agent client certificates.
#
#   ./scripts/generate-agent-certs.sh --ca                   # create the CA once
#   ./scripts/generate-agent-certs.sh --manager <fqdn|ip>... # manager cert (agents verify it)
#   ./scripts/generate-agent-certs.sh <agent-name> ...       # one key+cert per agent
#
# Output: config/agent_ssl_certs/{rootCA.pem,rootCA.key}
#         config/agent_ssl_certs/manager/{sslmanager.cert,sslmanager.key}
#         config/agent_ssl_certs/agents/<name>/{sslagent.cert,sslagent.key,rootCA.pem}
# Then set AGENT_CERT_VERIFICATION=true in .env and run scripts/setup.sh
# (or render + enable-enrollment.sh). Keep rootCA.key offline if you can.
source "$(dirname "$0")/lib.sh"
require openssl
DIR="$ROOT/config/agent_ssl_certs"
DAYS="${DAYS:-825}"

[[ $# -ge 1 ]] || die "usage: $0 --ca | <agent-name> [agent-name ...]"

if [[ "$1" == "--ca" ]]; then
  [[ -f "$DIR/rootCA.key" ]] && die "agent CA already exists in $DIR"
  mkdir -p "$DIR"; chmod 750 "$DIR"
  ( umask 077; openssl genrsa -out "$DIR/rootCA.key" 4096 2>/dev/null )
  openssl req -x509 -new -nodes -key "$DIR/rootCA.key" -sha256 -days 3650 \
    -subj "/C=US/O=Wazuh/OU=Agents/CN=Wazuh Agent CA" -out "$DIR/rootCA.pem"
  chmod 644 "$DIR/rootCA.pem"
  ok "Agent CA created: $DIR/rootCA.pem"
  exit 0
fi

[[ -f "$DIR/rootCA.key" ]] || die "no agent CA yet - run: $0 --ca"

if [[ "$1" == "--manager" ]]; then
  shift; [[ $# -ge 1 ]] || die "usage: $0 --manager <fqdn|ip> [more names...]"
  out="$DIR/manager"; mkdir -p "$out"
  san=""
  for n in "$@" wazuh.manager; do
    if [[ "$n" =~ ^[0-9.]+$ || "$n" == *:* ]]; then san+="IP:$n,"; else san+="DNS:$n,"; fi
  done
  ( umask 077; openssl genrsa -out "$out/sslmanager.key" 2048 2>/dev/null )
  openssl req -new -key "$out/sslmanager.key" -subj "/C=US/O=Wazuh/OU=Manager/CN=$1" -out "$out/sslmanager.csr"
  openssl x509 -req -in "$out/sslmanager.csr" -CA "$DIR/rootCA.pem" -CAkey "$DIR/rootCA.key" \
    -CAcreateserial -out "$out/sslmanager.cert" -days "$DAYS" -sha256 \
    -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "${san%,}") 2>/dev/null
  rm -f "$out/sslmanager.csr"
  ok "Manager certificate in $out (installed by scripts/enable-enrollment.sh)"
  exit 0
fi

for name in "$@"; do
  [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid agent name: $name"
  out="$DIR/agents/$name"; mkdir -p "$out"
  ( umask 077; openssl genrsa -out "$out/sslagent.key" 2048 2>/dev/null )
  openssl req -new -key "$out/sslagent.key" -subj "/C=US/O=Wazuh/OU=Agents/CN=$name" -out "$out/sslagent.csr"
  openssl x509 -req -in "$out/sslagent.csr" -CA "$DIR/rootCA.pem" -CAkey "$DIR/rootCA.key" \
    -CAcreateserial -out "$out/sslagent.cert" -days "$DAYS" -sha256 \
    -extfile <(printf 'extendedKeyUsage=clientAuth\n') 2>/dev/null
  rm -f "$out/sslagent.csr"; cp "$DIR/rootCA.pem" "$out/rootCA.pem"
  ok "Agent certificate for '$name' in $out (copy to the agent's /var/ossec/etc/)"
done
