# 4. Integrating MISP, TheHive and Cortex

```
                 ┌──────────── IoC lookup (custom-misp) ───────────┐
                 │                                                  ▼
 agents ─▶ Wazuh manager ──── alerts ≥ level 7 (custom-thehive) ─▶ TheHive 5 ──▶ cases
             ▲    │                                                  │
             │    └─ MISP hit → rules 100622-100624 (level 12-14) ───┘ (sent to TheHive too)
             │                                                        │ run analyzers /
             │                                                        ▼ responders
             │                                                     Cortex 3 ──▶ MISP, AbuseIPDB, VT...
             └──────────── (optional) Wazuh responder / active response ◀─┘
```

| Direction | How | Where |
|---|---|---|
| Wazuh → MISP | `custom-misp` integration looks up hashes, IPs and domains from each alert with `/attributes/restSearch` and writes hits back as events | `integrations/wazuh/custom-misp.py`, `config/wazuh_rules/misp_rules.xml` |
| Wazuh → TheHive | `custom-thehive` integration creates a TheHive alert (with observables) for every alert at or above `THEHIVE_MIN_LEVEL` | `integrations/wazuh/custom-thehive.py` |
| TheHive → Cortex | Cortex connector in TheHive runs analyzers on the observables | TheHive UI |
| Cortex → MISP | `MISP_2_1` analyzer | Cortex UI |
| TheHive ↔ MISP | MISP connector: import MISP events as alerts, export cases as events | TheHive UI |

For automation on top of this (playbooks, active response, notifications),
see [doc 5: Shuffle](05-shuffle.md). Its enrichment workflow reuses the same
TheHive alert when both paths fire.

You can use the bundled containers (`docker-compose.soar.yml`) or instances you
already run. For existing instances, skip step 1 and point `MISP_URL` and
`THEHIVE_URL` at them.

---

## Step 1: Start the SOAR stack (optional)

```bash
sed -i 's/^ENABLE_SOAR_STACK=.*/ENABLE_SOAR_STACK=true/' .env
# set MISP_BASE_URL to the URL analysts will use, e.g. https://soc.example.com:8443
./scripts/setup.sh                 # adds docker-compose.soar.yml automatically
docker compose -f docker-compose.yml -f docker-compose.soar.yml ps
```

The first start takes a few minutes: MISP initializes its database and
Cassandra bootstraps. Services:

| Service | URL | First login |
|---|---|---|
| MISP | `https://<host>:8443` | `MISP_ADMIN_EMAIL` / `MISP_ADMIN_PASSWORD` |
| TheHive | `http://<host>:9000` | `admin@thehive.local` / `secret`. **Change it now.** |
| Cortex | `http://<host>:9001` | create the superadmin on first visit |

> Put TheHive and Cortex behind a TLS reverse proxy (nginx, Traefik) before
> exposing them outside the host. Cortex mounts `/var/run/docker.sock` to
> run analyzers, which is equivalent to root on the host. Run the stack on a
> dedicated, isolated VM.

---

## Step 2: MISP

1. Log in and change the admin password if you are asked to.
2. **Feeds:** *Sync Actions > Feeds > Load default feed metadata*, enable
   for example *CIRCL OSINT Feed* and *abuse.ch* feeds, and use *Fetch and store
   all feed data*. Schedule it under *Administration > Scheduled tasks*.
3. **Service account for Wazuh (read only):**
   - *Administration > Add User*: `wazuh@<org>`, role **Read Only**, your org.
   - *Administration > List Auth Keys > Add authentication key* for that user.
     Optionally restrict *Allowed IPs* to the Docker host.
4. Put the key in `.env`:

   ```ini
   ENABLE_MISP=true
   MISP_URL=https://misp-core          # service name inside Docker; or https://misp.example.com
   MISP_API_KEY=<the auth key>
   MISP_VERIFY_SSL=false               # true once MISP has a certificate the manager trusts
   ```

5. Test from the manager container:

   ```bash
   docker compose exec wazuh.manager curl -sk -H "Authorization: <key>" \
     -H 'Accept: application/json' https://misp-core/servers/getVersion
   ```

**Which alerts are checked:** `MISP_RULE_GROUPS` (default: Sysmon events 1, 3,
6, 7, 15, 22 and FIM `syscheck`). The script extracts:

| Source | Indicator |
|---|---|
| Sysmon `hashes` / `hash` | SHA256 (falls back to MD5/SHA1) |
| Sysmon `destinationIp` / `sourceIp`, `data.srcip` / `data.dstip` | public IPs only |
| Sysmon 22 `queryName` | domain |
| FIM `sha256_after` | SHA256 |

**Resulting alerts** (`config/wazuh_rules/misp_rules.xml`):

| Rule | Level | Meaning |
|---|---|---|
| 100620 | 0 | base: event from the MISP integration |
| 100621 | 5 | MISP lookup failed (URL, key or TLS problem) |
| 100622 | 12 | IoC found in a MISP event |
| 100623 | 13 | IoC found and flagged `to_ids` |
| 100624 | 14 | `to_ids` file hash found (likely malware) |

---

## Step 3: Cortex

1. Open `http://<host>:9001`. Click **Update database**, then create the
   **superadmin** account.
2. *Organizations > Add organization*: `SOC`.
3. In `SOC`, *Users > Add user*:
   - `thehive` with role **read, analyze, orgadmin**. Click *Create API key*
     and copy it; TheHive uses this key.
4. *Organization > Analyzers*: enable what you need, for example:
   - **MISP_2_1**: URL `https://misp-core`, key from step 2 (a key with
     search rights), `cert_check=false` unless MISP has a trusted certificate.
   - **AbuseIPDB_1_0**, **VirusTotal_GetReport_3_1**, **Shodan_Host_1_0**,
     **URLhaus_2_0**, **MaxMind_GeoIP_4_0** (with your own API keys).
5. *Organization > Responders* (optional): the **Wazuh** responder can call
   the Wazuh API from a TheHive case, for example to block an IP. Give it a
   dedicated Wazuh API user with a restricted RBAC role, not `wazuh`.

Analyzers run as Docker containers pulled from Docker Hub, so the host needs
outbound access to registry-1.docker.io and to the analyzer catalog.

---

## Step 4: TheHive

1. Log in as `admin@thehive.local` / `secret`, then **change the password
   immediately** (avatar > *Settings*). Enable MFA.
2. *Organisations > +*: create `SOC`.
3. In `SOC`, create users:
   - Your analysts (profile `analyst` or `org-admin`).
   - `wazuh@soc.local`, type **Service**, profile **analyst**. Open the user,
     *Create API key*, copy it.
4. *Platform management > Connectors > Cortex > +*: server
   `http://cortex:9001`, API key from step 3.3, then *Test* and *Save*.
5. *Platform management > Connectors > MISP > +*: URL `https://misp-core`,
   the MISP key, and turn on *skip certificate check* if MISP uses a
   self-signed certificate. Choose import (MISP events → alerts) and/or
   export (cases → MISP events).
6. Put the Wazuh service key in `.env`:

   ```ini
   ENABLE_THEHIVE=true
   THEHIVE_URL=http://thehive:9000      # or https://thehive.example.com
   THEHIVE_API_KEY=<wazuh service user API key>
   THEHIVE_MIN_LEVEL=7                 # only alerts with rule.level >= 7
   ```

Each TheHive alert contains:

- **Title:** `[Wazuh] <rule description>`, with `sourceRef` set to the Wazuh
  alert ID.
- **Severity:** level 7-9 → Medium, 10-12 → High, 13+ → Critical.
- **Tags:** rule ID, level, agent, rule groups and MITRE technique IDs.
- **Observables:** agent host and IP, src/dst IPs, users, Sysmon hashes,
  image and DNS query, FIM path and hashes, and the MISP hit. Cortex
  analyzers run on these.
- **Description:** the full log and the complete alert JSON.

---

## Step 5: Apply the Wazuh side

```bash
./scripts/setup.sh    # re-renders ossec.conf with the <integration> blocks, restarts, installs scripts + rules
```

Or only the integration part, if the configuration is already rendered:

```bash
./scripts/install-integrations.sh
```

The rendered `ossec.conf` contains:

```xml
<integration>
  <name>custom-misp</name>
  <hook_url>https://misp-core</hook_url>
  <api_key>***</api_key>
  <group>sysmon_event1,sysmon_event3,...,syscheck</group>
  <alert_format>json</alert_format>
  <options>{"verify_ssl": false, "timeout": 10}</options>
</integration>

<integration>
  <name>custom-thehive</name>
  <hook_url>http://thehive:9000</hook_url>
  <api_key>***</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
  <options>{"verify_ssl": false, "timeout": 10, "tlp": 2, "pap": 2}</options>
</integration>
```

The scripts are installed as `/var/ossec/integrations/custom-*`
(`root:wazuh 750`). They run with Wazuh's bundled Python, which includes
`requests`, so nothing extra has to be installed in the container.

---

## Step 6: End-to-end test

The sample alert `integrations/wazuh/test-alert.json` contains the hashes of
the harmless **EICAR** test file.

1. In MISP, create an event "EICAR test" and add the attribute
   `sha256 = 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`
   with *for IDS* checked.
2. Run the integrations by hand inside the manager:

   ```bash
   docker compose exec wazuh.manager bash -c '
     K_MISP=$(grep -A3 "<name>custom-misp" /var/ossec/etc/ossec.conf | sed -n "s:.*<api_key>\(.*\)</api_key>.*:\1:p")
     K_HIVE=$(grep -A3 "<name>custom-thehive" /var/ossec/etc/ossec.conf | sed -n "s:.*<api_key>\(.*\)</api_key>.*:\1:p")
     echo "{\"verify_ssl\": false}" > /tmp/test.options
     /var/ossec/integrations/custom-misp    /opt/staging/integrations/test-alert.json "$K_MISP" https://misp-core   "" /tmp/test.options
     /var/ossec/integrations/custom-thehive /opt/staging/integrations/test-alert.json "$K_HIVE" http://thehive:9000 "" /tmp/test.options
     tail -n 5 /var/ossec/logs/integrations.log'
   ```

3. Expected results:
   - `integrations.log` shows `MISP hit for sha256=...` and `alert ... created in TheHive`.
   - Wazuh dashboard → *Threat Hunting*, filter `rule.groups: misp`: rule
     **100624** (level 14).
   - That MISP alert (level ≥ 7) is also forwarded to TheHive
     automatically.
   - TheHive → *Alerts*: `[Wazuh] TEST - integration smoke test`. Open it,
     select the SHA256 observable and run the **MISP_2_1** analyzer. Cortex
     reports the EICAR event.
4. Live test on a Windows agent with Sysmon: download the EICAR file.
   Sysmon event 15 (FileCreateStreamHash) or event 1 goes through MISP and
   ends up in TheHive. Defender may quarantine the file first; either way it
   shows up.

---

## Troubleshooting

| Symptom | Check |
|---|---|
| Nothing in `integrations.log` | `docker compose exec wazuh.manager grep -i integrator /var/ossec/logs/ossec.log`: is `wazuh-integratord` running? Do the alerts match the groups/level? |
| `Unable to run integration` / permission denied | re-run `./scripts/install-integrations.sh` (scripts must be `root:wazuh 750`) |
| Rule 100621 "MISP lookup failed" | URL, key or TLS: run the curl test in step 2.5 |
| TheHive HTTP 401 / 403 | wrong key, or the service user lacks the `manageAlert/create` permission (profile `analyst`) |
| TheHive HTTP 400 "already exists" | the same Wazuh alert was sent twice (same `sourceRef`); harmless |
| Cortex jobs stuck in *Waiting* | `docker.sock` mounted? Can the host pull analyzer images? Is `CORTEX_JOB_DIR` the same path on host and container? |
| Too many TheHive alerts | raise `THEHIVE_MIN_LEVEL`, or add `<group>` / `<rule_id>` filters to the rendered block in `wazuhctl.py` |
