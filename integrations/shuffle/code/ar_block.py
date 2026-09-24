# Step "ar_block": trigger the Wazuh active response on the agent that saw the attack.
DECISION = load(r"""$ar_decide.message""")
API = cfg("$wazuh_api_url").rstrip("/")
USER = cfg("$wazuh_api_user")
PASSWORD = cfg("$wazuh_api_password")
COMMAND = cfg("$ar_command", "!firewall-drop")

out = {"blocked": False, "ip": DECISION.get("ip"), "agent_id": DECISION.get("agent_id")}
try:
    r = requests.post(API + "/security/user/authenticate?raw=true", auth=(USER, PASSWORD),
                      verify=False, timeout=20)
    r.raise_for_status()
    token = r.text.strip()
    r = requests.put(API + "/active-response?agents_list=%s" % DECISION["agent_id"],
                     headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
                     json={"command": COMMAND, "arguments": [],
                           "alert": {"data": {"srcip": DECISION["ip"]}}},
                     verify=False, timeout=20)
    res = r.json()
    out["response"] = res.get("message")
    out["blocked"] = r.ok and res.get("data", {}).get("total_affected_items", 0) > 0
    if not out["blocked"]:
        out["error"] = json.dumps(res.get("data", {}).get("failed_items", res))[:500]
except Exception as exc:
    out["error"] = str(exc)[:500]
emit(out)
