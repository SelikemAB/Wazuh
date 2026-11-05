# Step "enrich_thehive": create the TheHive alert and promote it to a case
# when it is severe enough or MISP matched. If the direct Wazuh->TheHive
# integration already created the alert (same type/source/sourceRef), reuse it.
ALERT = load(r"""$exec.all_fields""")
EXTRACT = load(r"""$enrich_extract.message""")
MISP = load(r"""$enrich_misp.message""")
URL = cfg("$thehive_url").rstrip("/")
KEY = cfg("$thehive_api_key")
ORG = cfg("$thehive_organisation")
CASE_LEVEL = as_int(cfg("$case_min_level", "12"), 12)
VERIFY = as_bool(cfg("$verify_ssl", "false"))

HEADERS = {"Authorization": "Bearer " + KEY, "Content-Type": "application/json"}
if ORG:
    HEADERS["X-Organisation"] = ORG


def severity(level):
    return 4 if level >= 13 else 3 if level >= 10 else 2 if level >= 7 else 1


def find_existing(source_ref):
    query = {"query": [{"_name": "listAlert"},
                       {"_name": "filter", "_and": [{"_field": "type", "_value": "wazuh"},
                                                    {"_field": "source", "_value": "wazuh"},
                                                    {"_field": "sourceRef", "_value": source_ref}]}]}
    resp = requests.post(URL + "/api/v1/query", headers=HEADERS, json=query, verify=VERIFY, timeout=20)
    resp.raise_for_status()
    items = resp.json()
    return items[0] if items else None


rule = ALERT.get("rule", {}) or {}
agent = ALERT.get("agent", {}) or {}
level = as_int(rule.get("level"), 0)
hits = MISP.get("hits", [])
hit_values = {h.get("value") for h in hits}

tags = ["wazuh", "shuffle", "rule:%s" % rule.get("id"), "level:%s" % level,
        "agent:%s" % agent.get("name", "manager")]
tags += ["group:" + g for g in rule.get("groups", []) or []]
tags += ["mitre:" + t for t in ((rule.get("mitre") or {}).get("id") or [])]
tags += ["misp:event-%s" % h.get("event_id") for h in hits][:10]

obs = []
for o in EXTRACT.get("observables", []):
    item = {"dataType": o["dataType"], "data": o["data"], "message": o["message"]}
    if o["data"] in hit_values:
        item["ioc"] = True
        item["tags"] = ["misp-hit"]
    obs.append(item)

misp_md = ""
if hits:
    misp_md = "\n\n**MISP matches:**\n" + "\n".join(
        "- `%s` (%s) - event %s: %s%s" % (h["value"], h["type"], h["event_id"], h["event_info"],
                                          " **[to_ids]**" if h.get("to_ids") else "")
        for h in hits[:20])

body = {
    "type": "wazuh",
    "source": "wazuh",
    "sourceRef": str(ALERT.get("id")),
    "title": ("[Wazuh] " + str(rule.get("description", "alert")))[:512],
    "description": "**Rule:** %s - %s (level %s)\n**Agent:** %s (%s) %s\n**Location:** %s\n**Timestamp:** %s%s\n\n```\n%s\n```" % (
        rule.get("id"), rule.get("description"), level, agent.get("name"), agent.get("id"),
        agent.get("ip", ""), ALERT.get("location"), ALERT.get("timestamp"), misp_md,
        str(ALERT.get("full_log", ""))[:4000]),
    "severity": min(4, severity(level) + (1 if hits else 0)),
    "tlp": 2,
    "pap": 2,
    "tags": tags[:50],
    "observables": obs,
}

out = {"alert_id": None, "case_id": None, "created": False}
try:
    resp = requests.post(URL + "/api/v1/alert", headers=HEADERS, json=body, verify=VERIFY, timeout=20)
    if resp.status_code in (200, 201):
        alert = resp.json()
        out["created"] = True
    else:
        alert = find_existing(body["sourceRef"])
        if not alert:
            raise RuntimeError("HTTP %s: %s" % (resp.status_code, resp.text[:300]))
    out["alert_id"] = alert.get("_id")
    out["case_id"] = alert.get("caseId")

    if not out["case_id"] and (level >= CASE_LEVEL or hits):
        resp = requests.post(URL + "/api/v1/alert/%s/case" % out["alert_id"], headers=HEADERS,
                             json={}, verify=VERIFY, timeout=20)
        resp.raise_for_status()
        out["case_id"] = resp.json().get("_id")
        out["case_number"] = resp.json().get("number")
except Exception as exc:
    out["error"] = str(exc)[:500]
emit(out)
