# 5. Shuffle SOAR

[Shuffle](https://shuffler.io) is the automation layer. It is added to the
existing integrations and replaces none of them:

| Path | Still active? | Purpose |
|---|---|---|
| Wazuh → MISP (`custom-misp`) | yes | IoC matches become Wazuh alerts (rules 100620-100624) |
| Wazuh → TheHive (`custom-thehive`) | yes (optional) | direct alert forwarding at `THEHIVE_MIN_LEVEL` |
| **Wazuh → Shuffle** (built-in `shuffle` integration) | **new** | **every** alert is posted to the Shuffle webhooks |

```
                                ┌─────────────────────────── Shuffle ───────────────────────────┐
 Wazuh manager ── all alerts ──▶│ ① Enrich & TheHive case                                        │
  (integration "shuffle",       │    extract ─▶ MISP lookup ─▶ TheHive alert/case ─▶ Cortex ─▶   │──▶ TheHive case
   one block per webhook)       │    (level ≥ 10 or MISP hit)                    comment in case │
                                │ ② Auto-response                                                │
                                │    decide (rule list, allowlist) ─▶ Wazuh API active response  │──▶ agent firewall-drop
                                │ ③ Notification                                                 │
                                │    filter (level ≥ 12) ─▶ Slack / Teams / e-mail               │──▶ SOC channel
                                └────────────────────────────────────────────────────────────────┘
```

## What gets deployed

`docker-compose.shuffle.yml`, an overlay enabled with `ENABLE_SHUFFLE_STACK=true`:

| Service | Image | Notes |
|---|---|---|
| `shuffle-frontend` | `ghcr.io/shuffle/shuffle-frontend` | UI on `https://<host>:3443` (`SHUFFLE_PORT`) |
| `shuffle-backend` | `ghcr.io/shuffle/shuffle-backend` | API/webhooks on `:5001`, also reachable as `http://shuffle-backend:5001` from Wazuh |
| `shuffle-orborus` | `ghcr.io/shuffle/shuffle-orborus` | runs workflow workers and apps as sibling containers |
| `shuffle-opensearch` | `opensearchproject/opensearch` | Shuffle's own database. Separate from the Wazuh indexer and not published |

Security:

- The first admin account and its API key are created at boot from `.env`
  (`SHUFFLE_ADMIN_*`). The open "register the first admin" page is never
  exposed.
- Stored app credentials are encrypted with `SHUFFLE_ENCRYPTION_MODIFIER`.
- Auto-response uses a dedicated Wazuh API user, `shuffle-ar`, whose RBAC
  role only allows `active-response:command`. It cannot read or change
  anything else.
- The backend and orborus mount `/var/run/docker.sock`, which is equivalent
  to root on the host. Firewall 3443/5001 to the SOC network and keep this
  host dedicated to security tooling.

## Requirements

- About 4 GB of additional RAM (OpenSearch + workers).
- `SOAR_HOST_ADDRESS`: the Docker host's LAN IP or FQDN. Shuffle's app
  containers are started outside the compose network, so they reach MISP,
  TheHive, Cortex and the Wazuh API through this address and the published
  ports.
- `API_BIND` must not be `127.0.0.1`, otherwise the apps cannot reach the
  Wazuh API.
- Outbound access to `ghcr.io` and `github.com` (Shuffle downloads its apps on
  first start).

## Deploy

```bash
# in .env
ENABLE_SHUFFLE_STACK=true
SOAR_HOST_ADDRESS=10.10.0.5          # this host
# optional keys used by the workflows (can also be edited in Shuffle later):
THEHIVE_API_KEY=...                  # shared with the direct TheHive integration
MISP_API_KEY=...
SHUFFLE_CORTEX_API_KEY=...
SHUFFLE_SLACK_WEBHOOK_URL=... / SHUFFLE_TEAMS_WEBHOOK_URL=... / SHUFFLE_SMTP_*

./scripts/setup.sh           # full stack; calls shuffle-setup.sh at the end
# or, if Wazuh is already running:
./scripts/shuffle-setup.sh
```

`shuffle-setup.sh`:

1. Starts the four Shuffle containers and waits for the backend.
2. Creates or refreshes the Wazuh API user `shuffle-ar`
   (`wazuhctl.py api-create-shuffle-user`: policy
   `active-response:command` on `agent:id:*` → role → user).
3. Builds the three workflows from `integrations/shuffle/code/`, imports them
   through the Shuffle API (`POST/PUT /api/v1/workflows`) and starts their
   webhooks.
4. Writes `ENABLE_SHUFFLE=true` and `SHUFFLE_WEBHOOK_URLS` to `.env`,
   re-renders `ossec.conf` with one `<integration>` block per webhook, and
   restarts the manager.

It is idempotent. Workflow, step and trigger IDs are deterministic, so
re-running it updates the same workflows and **keeps the webhook URLs**.

### Wazuh side (rendered into `ossec.conf`)

```xml
<integration>
  <name>shuffle</name>
  <hook_url>http://shuffle-backend:5001/api/v1/hooks/webhook_740af714-...</hook_url>
  <alert_format>json</alert_format>
  <!-- no <level>: every alert (>= log_alert_level 3) is forwarded -->
</integration>
<!-- ... one block per workflow webhook ... -->
```

**Volume.** With "everything" forwarded, every alert starts **three**
executions (one per workflow), and most of them stop at the first filter step.
On a busy manager, cut this down with `SHUFFLE_MIN_LEVEL=5` (adds `<level>`),
or drop a workflow's URL from `SHUFFLE_WEBHOOK_URLS`, then re-run
`scripts/setup.sh`. Wazuh's `shuffle.py` already skips a few noisy rule IDs
(for example 5710 and some AWS/GCP rules).

Payload received by Shuffle: `{severity, pretext, title, text, rule_id,
timestamp, id, all_fields: <full Wazuh alert>}`. The workflows read
`$exec.all_fields`.

## The starter workflows

Every step is a **Shuffle Tools → Execute python** action. The source code is
in `integrations/shuffle/code/<step>.py`, with `_common.py` prepended when the
workflows are built. Settings are **workflow variables** (right panel →
*Variables* in the workflow editor), filled from `.env` at import.

### ① Wazuh - Enrich & TheHive case

| Step | Does |
|---|---|
| `enrich_extract` | gate: continues only if `rule.level ≥ thehive_min_level` (10) **or** the alert is a MISP hit. Builds observables (IPs, hashes, domains, host, user, files). |
| `enrich_misp` | one MISP `restSearch` with all IoCs (OR). Errors don't stop the chain. |
| `enrich_thehive` | creates the TheHive alert (MISP matches are flagged as IoCs and raise the severity by one). If the direct `custom-thehive` integration already created it (same `type/source/sourceRef`), reuses that alert. Promotes it to a **case** when `level ≥ case_min_level` (12) or MISP matched. |
| `enrich_cortex` | runs the analyzers listed in `cortex_analyzers` (default `MISP_2_1,AbuseIPDB_1_0`) on the IoC observables (max 10 jobs), waits for up to 1 minute each, and posts a result table as a **case comment**. |

Variables: `misp_url`, `misp_api_key`, `thehive_url`, `thehive_api_key`,
`thehive_organisation`, `thehive_min_level`, `case_min_level`, `cortex_url`,
`cortex_api_key`, `cortex_analyzers`, `verify_ssl`.

Keys:

- **TheHive:** reuse the `wazuh` service user (profile *analyst*: can create
  alerts, cases and comments).
- **Cortex:** create a user `shuffle` in the `SOC` org with role
  **read, analyze** and put its key in `SHUFFLE_CORTEX_API_KEY`. Analyzer
  names must match exactly what you enabled in Cortex.

### ② Wazuh - Auto-response (block IP)

| Step | Does |
|---|---|
| `ar_decide` | gate: `rule.id` is in `ar_rule_ids`, a source IP exists (`data.srcip`, or the value of a MISP IP hit), the IP is **not** in `ar_allowlist`, and the alert came from an agent (not `000`). |
| `ar_block` | logs in to the Wazuh API as `shuffle-ar` and runs `PUT /active-response?agents_list=<agent>` with `!firewall-drop` and `data.srcip`. |

Default rule IDs: `5712` (SSHD brute force), `5720` (multiple SSHD auth
failures), `5763` (SSHD brute force), `5551` (PAM multiple failures), `60204`
(Windows multiple logon failures), `31151` (web 400 errors from one source),
`100623`/`100624` (MISP `to_ids` hits).

Before you enable this in production:

- Put your VPN, NAT, scanner and management ranges in `SHUFFLE_AR_ALLOWLIST`.
  Blocking your own jump host is the classic failure.
- `firewall-drop` is a Linux/macOS agent script. For Windows agents use
  `!netsh.exe` (set `ar_command`) or split the workflow by OS.
- A block triggered through the API has **no automatic timeout**. Unblock
  with `iptables -D INPUT -s <ip> -j DROP` on the agent, or add a scheduled
  Shuffle workflow that removes it. For timed blocks driven by Wazuh itself,
  use an `<active-response>` block with `<timeout>` in `ossec.conf` instead.
- Test first with `ar_rule_ids` set to a rule you can trigger safely.

### ③ Wazuh - Notification

| Step | Does |
|---|---|
| `notify_filter` | gate: `rule.level ≥ notify_min_level` (12). |
| `notify_send` | posts to `slack_webhook_url` (Slack incoming webhook), `teams_webhook_url` (Teams **Workflows** webhook, adaptive card) and/or sends e-mail over SMTP with STARTTLS (`smtp_*`, `mail_from`, `mail_to`). Channels with an empty variable are skipped. |

## Importing by hand

The files in `integrations/shuffle/workflows/*.json` contain no secrets.
`SOAR_HOST_ADDRESS` appears as a placeholder in the URLs. The copies in
`secrets/shuffle/*.json` (mode 600, git-ignored) are filled from `.env`.

1. Shuffle → *Workflows* → *Import* → select the JSON.
2. Open the workflow, then *Variables*: fill the empty secrets and fix the
   URLs.
3. Click the **Webhook** node, then **Start**, and copy its URL. Replace the
   host part with `http://shuffle-backend:5001` (the name the manager
   resolves).
4. Add the URL to `SHUFFLE_WEBHOOK_URLS` (comma separated), set
   `ENABLE_SHUFFLE=true`, and run `./scripts/setup.sh`.

If a Shuffle version rejects the import, build the workflow by hand: add a
Webhook trigger and one *Shuffle Tools → Execute python* node per step, paste
`_common.py` + `<step>.py` into each node's `code` field, connect them in
order, and on the edge after the gate step add the condition
`$<gate>.message.proceed` **equals** `true`. The variables are listed above.

## Testing

```bash
# 1. Post the sample alert straight to a webhook, the same way Wazuh does
URL=$(grep ^SHUFFLE_WEBHOOK_URLS= .env | cut -d= -f2 | cut -d, -f1 | sed 's#shuffle-backend#127.0.0.1#')
python3 - "$URL" <<'PY'
import json, sys, urllib.request
alert = json.load(open("integrations/wazuh/test-alert.json"))
alert["rule"]["level"] = 13
body = {"severity": 3, "pretext": "WAZUH Alert", "title": alert["rule"]["description"],
        "text": alert["full_log"], "rule_id": alert["rule"]["id"], "timestamp": alert["timestamp"],
        "id": alert["id"], "all_fields": alert}
req = urllib.request.Request(sys.argv[1], json.dumps(body).encode(), {"Content-Type": "application/json"})
print(urllib.request.urlopen(req).read())
PY
# 2. Shuffle UI → workflow → "Explore runs": each step shows its JSON output
# 3. Live: failed SSH logins from an allowed test IP → rule 5712 → watch workflow ②
```

Troubleshooting:

| Symptom | Check |
|---|---|
| No executions | `docker compose exec wazuh.manager grep -i shuffle /var/ossec/logs/integrations.log /var/ossec/logs/ossec.log`; is the webhook started (Webhook node shows *running*)? |
| Executions stuck in *waiting* | `docker compose logs shuffle-orborus`; worker/app images pulled? `SOAR_HOST_ADDRESS` reachable from containers? |
| Step error `Connection refused` | the service isn't published on `SOAR_HOST_ADDRESS`, or `API_BIND=127.0.0.1` |
| `ar_block`: `failed_items` / 403 | re-run `shuffle-setup.sh` (recreates the `shuffle-ar` role); agent disconnected; `ar_command` not available on that OS |
| TheHive 401/403 | API key or organisation (`thehive_organisation` / `X-Organisation`) |
| A variable shows as `$name` in output | the variable is missing in the workflow. Re-import or add it under *Variables* |

## Upgrading

`SHUFFLE_VERSION=latest` by default. Pin a release tag once the stack is
stable, then `docker compose pull` and re-run `./scripts/shuffle-setup.sh`.
