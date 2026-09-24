# Step "ar_decide": should we block an IP for this alert?
ALERT = load(r"""$exec.all_fields""")
RULE_IDS = set(csv(cfg("$ar_rule_ids", "5712,5720,5763")))
ALLOWLIST = csv(cfg("$ar_allowlist", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8"))

rule = ALERT.get("rule", {}) or {}
data = ALERT.get("data", {}) or {}
agent = ALERT.get("agent", {}) or {}
out = {"proceed": False, "rule_id": rule.get("id"), "agent_id": agent.get("id")}

ip = data.get("srcip")
misp = data.get("misp", {}) or {}
if not ip and is_ip(misp.get("value", "")):
    ip = misp["value"]

if str(rule.get("id")) not in RULE_IDS:
    out["reason"] = "rule not in ar_rule_ids"
elif not ip or not is_ip(ip):
    out["reason"] = "no source IP in alert"
elif any(ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False) for net in ALLOWLIST):
    out["reason"] = "IP %s is allowlisted" % ip
elif not agent.get("id") or agent.get("id") == "000":
    out["reason"] = "alert did not come from an agent"
else:
    out.update({"proceed": True, "ip": ip, "reason": "block %s on agent %s" % (ip, agent.get("id"))})
emit(out)
