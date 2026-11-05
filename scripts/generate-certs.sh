#!/usr/bin/env bash
# Generate the TLS certificates for indexer, manager (Filebeat) and dashboard.
source "$(dirname "$0")/lib.sh"
CERT_DIR="$ROOT/config/wazuh_indexer_ssl_certs"

if [[ -f "$CERT_DIR/root-ca.pem" && "${1:-}" != "--force" ]]; then
  ok "Certificates already exist in $CERT_DIR (use --force to regenerate)"; exit 0
fi
# Keep the old certificates until the new ones exist, so a failed run
# (image pull, generator error) doesn't leave the stack without certs.
backup=""
if [[ -d "$CERT_DIR" ]]; then
  backup="$CERT_DIR.bak.$$"; mv "$CERT_DIR" "$backup"
fi
mkdir -p "$CERT_DIR"
log "Generating certificates with wazuh-certs-generator"
if ! docker compose --env-file "$ROOT/.env" -f "$ROOT/generate-indexer-certs.yml" run --rm generator    || [[ ! -f "$CERT_DIR/root-ca.pem" ]]; then
  rm -rf "$CERT_DIR"
  [[ -z "$backup" ]] || mv "$backup" "$CERT_DIR"
  die "certificate generation failed; previous certificates (if any) were restored"
fi
[[ -z "$backup" ]] || rm -rf "$backup"
# Note: the generator sets ownership/permissions the containers expect
# (the indexer runs as a non-root user), so don't tighten them blindly.
ok "Certificates written to $CERT_DIR"
