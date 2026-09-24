# Step "enrich_misp": look the IoCs up in MISP (one restSearch with OR semantics).
EXTRACT = load(r"""$enrich_extract.message""")
MISP_URL = cfg("$misp_url").rstrip("/")
MISP_KEY = cfg("$misp_api_key")
VERIFY = as_bool(cfg("$verify_ssl", "false"))

iocs = EXTRACT.get("iocs", [])
result = {"hit_count": 0, "hits": [], "checked": len(iocs)}
if iocs and MISP_URL and MISP_KEY:
    try:
        resp = requests.post(
            MISP_URL + "/attributes/restSearch",
            headers={"Authorization": MISP_KEY, "Accept": "application/json",
                     "Content-Type": "application/json"},
            json={"returnFormat": "json", "value": iocs, "limit": 50, "includeEventTags": 1},
            verify=VERIFY, timeout=20)
        resp.raise_for_status()
        for attr in resp.json().get("response", {}).get("Attribute", []):
            event = attr.get("Event", {}) or {}
            result["hits"].append({
                "value": attr.get("value"),
                "type": attr.get("type"),
                "to_ids": attr.get("to_ids"),
                "event_id": attr.get("event_id"),
                "event_info": event.get("info"),
                "tags": [t.get("name") for t in (attr.get("Tag") or []) if t.get("name")],
            })
        result["hit_count"] = len(result["hits"])
    except Exception as exc:  # keep the chain going; TheHive still gets the alert
        result["error"] = str(exc)[:300]
elif not (MISP_URL and MISP_KEY):
    result["error"] = "misp_url / misp_api_key workflow variables not set"
emit(result)
