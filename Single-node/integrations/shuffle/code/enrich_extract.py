# Step "enrich_extract": decide whether the alert goes to TheHive, collect observables.
ALERT = load(r"""$exec.all_fields""")
MIN_LEVEL = as_int(cfg("$thehive_min_level", "10"), 10)

rule = ALERT.get("rule", {}) or {}
level = as_int(rule.get("level"), 0)
groups = rule.get("groups", []) or []
obs = observables(ALERT)
proceed = bool(ALERT) and (level >= MIN_LEVEL or "misp" in groups)
emit({
    "proceed": proceed,
    "reason": "level %s vs threshold %s%s" % (level, MIN_LEVEL, ", MISP hit" if "misp" in groups else ""),
    "alert_id": ALERT.get("id"),
    "level": level,
    "observables": obs,
    "iocs": sorted({o["data"] for o in obs if o["ioc"]})[:25],
})
