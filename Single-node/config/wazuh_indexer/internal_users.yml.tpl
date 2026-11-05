---
# Rendered by scripts/render-configs.sh -> internal_users.yml (git-ignored).
# Only the two accounts the stack needs are defined. The demo accounts that
# ship with OpenSearch (kibanaro, logstash, readall, snapshotrestore) are
# intentionally omitted so no well-known credentials exist in the cluster.
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "${INDEXER_ADMIN_HASH}"
  reserved: true
  backend_roles:
  - "admin"
  description: "Wazuh indexer administrator"

kibanaserver:
  hash: "${DASHBOARD_KIBANASERVER_HASH}"
  reserved: true
  description: "Wazuh dashboard service user"
