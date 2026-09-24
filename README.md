# Wazuh on Docker: hardened boilerplate

A single-node Wazuh SIEM/XDR stack for Docker Compose, with:

- **No default credentials.** Indexer `admin` and `kibanaserver`, and the
  Wazuh API `wazuh` and `wazuh-wui` users, get unique generated passwords that
  are checked against a policy. The OpenSearch demo users are removed.
- **Secure agent enrollment.** `wazuh-authd` only enrolls agents that present
  the enrollment key. Agent client certificates (mutual TLS) can be required
  as a second factor.
- **Threat intel and SOAR.** Alerts are enriched against **MISP**, forwarded
  to **TheHive 5** as alerts with observables, and analyzed by **Cortex**.
  An optional compose overlay runs all three.

## Quick start

```bash
sudo sysctl -w vm.max_map_count=262144
./scripts/init-env.sh      # .env with random secrets (review it)
./scripts/setup.sh         # certs → configs → up → change passwords → enrollment → integrations
```

Dashboard: `https://<host>` · user `admin` · password `INDEXER_ADMIN_PASSWORD` in `.env`.

## Documentation

| # | Guide | Covers |
|---|---|---|
| 1 | [Deployment](docs/01-deployment.md) | requirements, layout, setup, ports/firewall, hardening, day-2 ops |
| 2 | [Secure agent enrollment](docs/02-agent-enrollment.md) | enrollment key, mutual TLS, Linux/Windows/macOS agents, verification, rotation |
| 3 | [Changing default passwords](docs/03-change-default-passwords.md) | indexer admin + API users: automated and manual procedures, rotation |
| 4 | [MISP, TheHive & Cortex](docs/04-integrations-misp-thehive-cortex.md) | architecture, setup of each tool, Wazuh integration, end-to-end test |

## Scripts

| Script | Purpose |
|---|---|
| `scripts/init-env.sh` | create `.env` from `.env.example` with generated secrets |
| `scripts/setup.sh` | full, idempotent deployment / re-apply after editing `.env` |
| `scripts/generate-certs.sh` | TLS for indexer, manager and dashboard (`--force` to regenerate) |
| `scripts/change-passwords.sh [indexer\|api\|all]` | change or rotate passwords on a running stack |
| `scripts/enable-enrollment.sh` | install or rotate the enrollment key (and agent CA / manager cert) |
| `scripts/generate-agent-certs.sh` | agent CA, manager cert and per-agent client certs |
| `scripts/install-integrations.sh` | install the MISP/TheHive scripts and MISP rules in the manager |
| `scripts/wazuhctl.py` | helper: `.env` parsing, policy check, template rendering, API password changes |

## Stack

| Component | Image | Port |
|---|---|---|
| Wazuh manager | `wazuh/wazuh-manager:${WAZUH_VERSION}` | 1514, 1515, 514/udp, 55000 |
| Wazuh indexer | `wazuh/wazuh-indexer:${WAZUH_VERSION}` | 127.0.0.1:9200 |
| Wazuh dashboard | `wazuh/wazuh-dashboard:${WAZUH_VERSION}` | 443 |
| MISP *(optional)* | `ghcr.io/misp/misp-docker/misp-core` | 8443 |
| TheHive 5 *(optional)* | `strangebee/thehive` | 9000 |
| Cortex 3 *(optional)* | `thehiveproject/cortex` | 9001 |

Secrets live only in `.env`, `secrets/` and the rendered configs, and all of
them are git-ignored. Keep `.env` in a password vault.
