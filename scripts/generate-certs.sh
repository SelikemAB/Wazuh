#!/usr/bin/env bash
# Generate the TLS certificates for indexer, manager (Filebeat) and dashboard.
source "$(dirname "$0")/lib.sh"
CERT_DIR="$ROOT/config/wazuh_indexer_ssl_certs"

if [[ -f "$CERT_DIR/root-ca.pem" && "${1:-}" != "--force" ]]; then
  ok "Certificates already exist in $CERT_DIR (use --force to regenerate)"; exit 0
fi
rm -rf "$CERT_DIR"; mkdir -p "$CERT_DIR"
log "Generating certificates with wazuh-certs-generator"
docker compose --env-file "$ROOT/.env" -f "$ROOT/generate-indexer-certs.yml" run --rm generator
# Note: the generator sets ownership/permissions the containers expect
# (the indexer runs as a non-root user), so don't tighten them blindly.
ok "Certificates written to $CERT_DIR"
