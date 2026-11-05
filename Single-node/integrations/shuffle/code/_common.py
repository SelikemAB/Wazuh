# ---------------------------------------------------------------------------
# Shared helpers, prepended to every step by scripts/shuffle_workflows.py.
# Each step runs in Shuffle's "Shuffle Tools > Execute python" action. Shuffle
# replaces the dollar-placeholders (workflow variables, the webhook body and
# earlier step results) in the code before running it; whatever the step
# prints becomes its result. Never write a literal dollar sign followed by a
# name anywhere in these files, including comments.
# ---------------------------------------------------------------------------
import ipaddress
import json

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def load(raw):
    """Parse a substituted JSON placeholder; {} if missing or not substituted."""
    raw = (raw or "").strip()
    if not raw or raw.startswith(chr(36)):
        return {}
    try:
        value = json.loads(raw)
    except ValueError:
        return {}
    # a step result may be a JSON string that itself contains JSON
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return {}
    return value


def cfg(raw, default=""):
    """Workflow variable, or default if Shuffle left the placeholder untouched."""
    raw = (raw or "").strip()
    return default if not raw or raw.startswith(chr(36)) else raw


def as_int(raw, default=0):
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return default


def as_bool(raw, default=False):
    raw = str(raw).strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default


def csv(raw):
    return [x.strip() for x in str(raw or "").split(",") if x.strip()]


def is_ip(value):
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def is_public_ip(value):
    try:
        return ipaddress.ip_address(str(value)).is_global
    except ValueError:
        return False


def emit(obj):
    print(json.dumps(obj))


def observables(alert):
    """Observables for TheHive/Cortex; 'ioc' marks values worth a MISP lookup."""
    obs = []

    def add(data_type, value, message, ioc=False):
        if value and isinstance(value, str):
            obs.append({"dataType": data_type, "data": value.strip(), "message": message, "ioc": ioc})

    data = alert.get("data", {}) or {}
    win = (data.get("win", {}) or {}).get("eventdata", {}) or {}
    agent = alert.get("agent", {}) or {}

    add("hostname", agent.get("name"), "Wazuh agent")
    if is_ip(agent.get("ip", "")):
        add("ip", agent["ip"], "Wazuh agent IP")
    for key in ("srcip", "dstip"):
        if is_ip(data.get(key, "")):
            add("ip", data[key], "data." + key, ioc=is_public_ip(data[key]))
    for key in ("srcuser", "dstuser"):
        add("other", data.get(key), "user (" + key + ")")
    for key in ("sourceIp", "destinationIp"):
        if is_ip(win.get(key, "")):
            add("ip", win[key], "sysmon " + key, ioc=is_public_ip(win[key]))
    if win.get("queryName"):
        add("domain", win["queryName"].rstrip(".").lower(), "sysmon DNS query", ioc=True)
    if win.get("image"):
        add("filename", win["image"], "sysmon image")
    for part in str(win.get("hashes") or win.get("hash") or "").split(","):
        if "=" in part:
            algo, _, value = part.partition("=")
            if algo.strip().upper() in ("MD5", "SHA1", "SHA256"):
                add("hash", value.strip().lower(), "sysmon " + algo.strip(), ioc=True)
    sc = alert.get("syscheck", {}) or {}
    if sc.get("path"):
        add("filename", sc["path"], "FIM path")
    for algo in ("md5_after", "sha1_after", "sha256_after"):
        add("hash", (sc.get(algo) or "").lower(), "FIM " + algo, ioc=True)
    misp = data.get("misp", {}) or {}
    if str(misp.get("found")) == "1" and misp.get("value"):
        dt = "ip" if is_ip(misp["value"]) else "hash" if misp.get("ioc_type") in ("md5", "sha1", "sha256") else "domain"
        add(dt, misp["value"], "MISP hit (event " + str(misp.get("event_id")) + ")", ioc=True)

    unique, seen = [], set()
    for o in obs:
        key = (o["dataType"], o["data"])
        if key not in seen:
            seen.add(key)
            unique.append(o)
    return unique
