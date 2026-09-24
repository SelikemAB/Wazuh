# Step "notify_filter": only notify for alerts at or above notify_min_level.
ALERT = load(r"""$exec.all_fields""")
MIN_LEVEL = as_int(cfg("$notify_min_level", "12"), 12)

rule = ALERT.get("rule", {}) or {}
agent = ALERT.get("agent", {}) or {}
level = as_int(rule.get("level"), 0)
emit({
    "proceed": bool(ALERT) and level >= MIN_LEVEL,
    "level": level,
    "title": "Wazuh level %s: %s" % (level, rule.get("description")),
    "rule_id": rule.get("id"),
    "agent": "%s (%s)" % (agent.get("name", "manager"), agent.get("id", "000")),
    "timestamp": ALERT.get("timestamp"),
    "alert_id": ALERT.get("id"),
    "groups": ", ".join(rule.get("groups", []) or []),
    "full_log": str(ALERT.get("full_log", ""))[:1500],
})
