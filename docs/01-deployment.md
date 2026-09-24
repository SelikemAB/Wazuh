# 1. Deploying Wazuh with Docker

Single-node Wazuh (manager, indexer, dashboard) based on the official
[`wazuh-docker`](https://github.com/wazuh/wazuh-docker) layout. The difference
is that no credentials are hardcoded: every secret comes from `.env`, and the
scripts replace every default password before the stack is used.

## Requirements

| Item | Minimum |
|---|---|
| OS | Linux x86_64 (Ubuntu 22.04/24.04, RHEL 9, ...) |
| CPU / RAM | 4 vCPU / 8 GB for Wazuh only; 8 vCPU / 16 GB with MISP + TheHive + Cortex |
| Disk | 50 GB+ SSD (alerts are stored in the indexer) |
| Software | Docker Engine 24+, Docker Compose v2, `python3`, `curl`, `openssl` |
| Kernel | `vm.max_map_count >= 262144` |

```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf
```

## Layout

```
docker-compose.yml             Wazuh manager + indexer + dashboard
docker-compose.soar.yml        optional MISP + TheHive + Cortex overlay
generate-indexer-certs.yml     one-shot TLS certificate generator
.env.example                   every tunable and secret (copied to .env)
config/
  certs.yml                    node names for the TLS certificates
  wazuh_cluster/*.conf.tpl     manager ossec.conf template (auth, integrations)
  wazuh_indexer/               opensearch.yml + internal_users.yml template
  wazuh_dashboard/             dashboard config + wazuh.yml template
  wazuh_rules/misp_rules.xml   MISP rules (100620-100624)
integrations/
  wazuh/                       custom-misp / custom-thehive scripts
  cortex/application.conf      Cortex configuration
scripts/                       setup, passwords, enrollment, integrations
```

Files rendered from templates (`internal_users.yml`, `wazuh.yml`,
`wazuh_manager.conf`) and everything in `secrets/` and the certificate
directories are git-ignored because they contain secrets.

## Quick start

```bash
git clone <this repo> wazuh-docker && cd wazuh-docker

# 1. Create .env with unique random secrets (mode 600)
./scripts/init-env.sh

# 2. Review .env: WAZUH_VERSION, ports, API_BIND, integrations
vi .env

# 3. Deploy: certs -> configs -> start -> change default passwords ->
#    enrollment key -> integrations
./scripts/setup.sh
```

`setup.sh` is idempotent; re-run it after editing `.env`.

Log in at `https://<host>` with `admin` and the `INDEXER_ADMIN_PASSWORD` from
`.env`.

## What `setup.sh` does

1. Checks Docker, Compose v2 and `vm.max_map_count`.
2. Creates `.env` if missing and runs the **credential policy check**: all
   passwords must be set, unique, 12-64 characters with upper, lower, digit and
   one of `. * + ? -`, and none may be a known default (`admin`,
   `SecretPassword`, `wazuh`, `MyS3cr37P450r.*-`, ...).
3. Generates the TLS certificates with `wazuh-certs-generator`, unless they
   already exist.
4. bcrypt-hashes the indexer passwords with the indexer's own `hash.sh` and
   renders `internal_users.yml`, `wazuh.yml` and `ossec.conf`.
5. Runs `docker compose up -d` and waits for the API.
6. Replaces the Wazuh API passwords of `wazuh` and `wazuh-wui`
   ([doc 3](03-change-default-passwords.md)).
7. Installs the enrollment key and enables password enrollment
   ([doc 2](02-agent-enrollment.md)).
8. Installs the MISP and TheHive integration scripts and rules
   ([doc 4](04-integrations-misp-thehive-cortex.md)).

## Manual steps (what the script automates)

```bash
cp .env.example .env && chmod 600 .env        # replace every __GENERATE*__ token
python3 scripts/wazuhctl.py validate
docker compose -f generate-indexer-certs.yml run --rm generator
# render the templates (hashes come from the indexer's hash.sh, see doc 3)
bash -c 'source scripts/lib.sh && render_configs'
docker compose up -d
docker compose ps
docker compose logs -f wazuh.manager
./scripts/change-passwords.sh api             # doc 3
./scripts/enable-enrollment.sh                # doc 2
./scripts/install-integrations.sh             # doc 4
```

## Ports and firewall

| Port | Service | Expose to |
|---|---|---|
| 443/tcp | Dashboard | SOC analysts (VPN / admin network) |
| 1514/tcp | Agent events | Agent networks only |
| 1515/tcp | Agent enrollment | Agent networks only (close it when you are not enrolling) |
| 514/udp | Syslog | Syslog sources only; remove it from the compose file if unused |
| 55000/tcp | Wazuh API | Admins only; set `API_BIND=127.0.0.1` if nothing external uses it |
| 9200/tcp | Indexer | Bound to `127.0.0.1` |
| 8443 / 9000 / 9001 | MISP / TheHive / Cortex | SOC analysts only |

Example with `ufw`:

```bash
sudo ufw allow from 10.0.0.0/8 to any port 1514,1515 proto tcp
sudo ufw allow from 10.10.0.0/24 to any port 443 proto tcp   # SOC network
```

> Docker publishes ports through iptables and bypasses `ufw` rules by default.
> Use the `DOCKER-USER` chain or a host/cloud firewall in front of the host.

## Production hardening checklist

- [ ] Pin `WAZUH_VERSION` and the SOAR image tags; upgrade on purpose.
- [ ] Put the dashboard behind a certificate from your CA: replace
      `wazuh.dashboard.pem` / `-key.pem`, or front it with a reverse proxy.
- [ ] Back up the Docker volumes (`wazuh_etc` holds `client.keys`) and `.env`.
- [ ] Rotate passwords on a schedule ([doc 3](03-change-default-passwords.md)).
- [ ] Create named dashboard users with least-privilege roles instead of
      sharing `admin` (Indexer management > Security).
- [ ] Forward `/var/ossec/logs/ossec.log` and the Docker logs to your log store.

## Day-2 operations

```bash
docker compose ps                                   # health
docker compose logs -f wazuh.manager                # logs
docker compose exec wazuh.manager /var/ossec/bin/agent_control -l   # agents
docker compose restart wazuh.manager                # apply ossec.conf changes
docker compose down                                 # stop, keep data
docker compose down -v                              # stop and DELETE ALL DATA
```

Upgrade: change `WAZUH_VERSION` in `.env`, read the Wazuh release notes, then
`docker compose pull && ./scripts/setup.sh`.
