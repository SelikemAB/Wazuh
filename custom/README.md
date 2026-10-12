# Custom Wazuh rules and decoders

Everything here is installed into the manager by `scripts/install-integrations.sh`
(also run by `scripts/setup.sh`):

| Repo folder | Installed to | Owner / mode |
|---|---|---|
| `custom/decoders/*.xml` | `/var/ossec/etc/decoders/` | `wazuh:wazuh 660` |
| `custom/rules/*.xml` | `/var/ossec/etc/rules/` | `wazuh:wazuh 660` |

The script runs `wazuh-analysisd -t` after copying. If the ruleset doesn't load,
**all** changes are rolled back (replaced files restored, new files removed) and
the manager is not restarted, so a typo can't take detection down.

## Rule ID map

Custom rules must use IDs **100000–120000**, and each file gets its own block so
IDs never collide:

| Range | File | Purpose |
|---|---|---|
| 100620–100629 | `rules/misp_rules.xml` | MISP IoC matches (`custom-misp` integration) |
| 100100–100199 | *(free)* | |
| 100200–100299 | *(free)* | |

Add a row when you add a file.

## Conventions

- One file per log source or use case, e.g. `decoders/fortigate_decoders.xml` +
  `rules/fortigate_rules.xml`. Don't edit Wazuh's stock `ruleset/` files; they
  are overwritten on upgrade.
- Decoder names must be unique across the whole ruleset. Prefix yours
  (e.g. `custom-fortigate`).
- Child rules use `<if_sid>`/`<if_group>`; set `<group>` so alerts are easy to
  filter in the dashboard and to forward with `<integration><group>`.
- Map rules to MITRE ATT&CK (`<mitre><id>T1110</id></mitre>`) where it applies.
- Levels: 0 = silent base rule, 3–6 = informational, 7–11 = investigate (sent to
  TheHive at the default `THEHIVE_MIN_LEVEL=7`), 12+ = high severity.

## Test before you commit

Paste a sample log line into `wazuh-logtest` on the running manager:

```bash
docker compose exec wazuh.manager /var/ossec/bin/wazuh-logtest
```

Check that phase 2 shows your decoder and fields, and phase 3 shows your rule
ID and level. Then install:

```bash
./scripts/install-integrations.sh
```
