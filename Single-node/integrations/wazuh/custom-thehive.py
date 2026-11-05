#!/usr/bin/env python3
"""Wazuh -> TheHive 5 alert forwarder.

Called by wazuh-integratord for every alert at or above the <level> of the
`custom-thehive` <integration> block:

    custom-thehive <alert_file> <api_key> <hook_url> [<...options>]

Creates a TheHive alert through POST /api/v1/alert with the Wazuh alert as
markdown, a severity derived from the rule level, and observables (IPs,
hashes, domains, host, user, MISP hit) that Cortex analyzers can run on.
"""
import ipaddress
import json
import os
import sys
import time

import requests
import urllib3

WAZUH_PATH = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
LOG_FILE = os.path.join(WAZUH_PATH, "logs", "integrations.log")


def log(msg):
    with open(LOG_FILE, "a") as fh:
        fh.write(f"{time.strftime('%Y/%m/%d %H:%M:%S')} custom-thehive: {msg}\n")


def load_options(args):
    for arg in args[4:]:
        if arg.endswith("options"):
            try:
                with open(arg) as fh:
                    return json.load(fh)
            except (OSError, ValueError) as exc:
                log(f"cannot read options file {arg}: {exc}")
    return {}


def severity(level):
    """Wazuh rule level (0-15) -> TheHive severity (1 low .. 4 critical)."""
    level = int(level or 0)
    if level >= 13:
        return 4
    if level >= 10:
        return 3
    if level >= 7:
        return 2
    return 1


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def observables(alert):
    obs = []

    def add(data_type, value, message):
        if value and isinstance(value, str):
            obs.append({"dataType": data_type, "data": value.strip(), "message": message})

    data = alert.get("data", {})
    win = data.get("win", {}).get("eventdata", {})
    agent = alert.get("agent", {})

    add("hostname", agent.get("name"), "Wazuh agent")
    if agent.get("ip") and is_ip(agent["ip"]):
        add("ip", agent["ip"], "Wazuh agent IP")
    for key in ("srcip", "dstip"):
        if is_ip(data.get(key, "")):
            add("ip", data[key], f"data.{key}")
    for key in ("srcuser", "dstuser"):
        add("other", data.get(key), f"user ({key})")
    for key in ("sourceIp", "destinationIp"):
        if is_ip(win.get(key, "")):
            add("ip", win[key], f"sysmon {key}")
    if win.get("queryName"):
        add("domain", win["queryName"].rstrip("."), "sysmon DNS query")
    if win.get("image"):
        add("filename", win["image"], "sysmon image")
    for part in (win.get("hashes") or "").split(","):
        if "=" in part:
            algo, _, value = part.partition("=")
            if algo.strip().upper() in ("MD5", "SHA1", "SHA256"):
                add("hash", value.lower(), f"sysmon {algo.strip()}")
    sc = alert.get("syscheck", {})
    if sc.get("path"):
        add("filename", sc["path"], "FIM path")
    for algo in ("md5_after", "sha1_after", "sha256_after"):
        add("hash", sc.get(algo), f"FIM {algo}")
    misp = data.get("misp", {})
    if misp.get("found") in (1, "1") and misp.get("value"):
        data_type = "ip" if is_ip(misp["value"]) else "hash" if misp.get("ioc_type") in (
            "md5", "sha1", "sha256") else "domain"
        add(data_type, misp["value"], f"MISP hit, event {misp.get('event_id')}: {misp.get('event_info')}")

    unique, seen = [], set()
    for o in obs:
        key = (o["dataType"], o["data"])
        if key not in seen:
            seen.add(key)
            unique.append(o)
    return unique


def build_alert(alert, options):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    level = rule.get("level", 0)
    tags = ["wazuh", f"rule:{rule.get('id')}", f"level:{level}", f"agent:{agent.get('name', 'manager')}"]
    tags += [f"group:{g}" for g in rule.get("groups", [])]
    for framework in ("mitre", "pci_dss", "gdpr", "hipaa", "nist_800_53"):
        value = rule.get(framework)
        if isinstance(value, dict):
            tags += [f"mitre:{t}" for t in value.get("id", [])]
        elif isinstance(value, list):
            tags += [f"{framework}:{v}" for v in value]

    description = "\n".join([
        f"**Rule:** {rule.get('id')} - {rule.get('description')} (level {level})",
        f"**Agent:** {agent.get('name')} ({agent.get('id')}) {agent.get('ip', '')}",
        f"**Location:** {alert.get('location')}",
        f"**Timestamp:** {alert.get('timestamp')}",
        "",
        "**Full log:**",
        "```",
        str(alert.get("full_log", ""))[:4000],
        "```",
        "",
        "**Alert JSON:**",
        "```json",
        json.dumps(alert, indent=2)[:20000],
        "```",
    ])
    return {
        "type": "wazuh",
        "source": options.get("source", "wazuh"),
        "sourceRef": str(alert.get("id") or time.time()),
        "title": f"[Wazuh] {rule.get('description', 'alert')}"[:512],
        "description": description,
        "severity": severity(level),
        "tlp": int(options.get("tlp", 2)),
        "pap": int(options.get("pap", 2)),
        "tags": tags[:50],
        "observables": observables(alert),
    }


def main(args):
    if len(args) < 4:
        log(f"wrong arguments: {args}")
        sys.exit(2)
    alert_file, api_key, hook_url = args[1], args[2], args[3]
    options = load_options(args)
    verify = bool(options.get("verify_ssl", True))
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    with open(alert_file) as fh:
        alert = json.load(fh)

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    if options.get("organisation"):
        headers["X-Organisation"] = options["organisation"]
    body = build_alert(alert, options)
    resp = requests.post(hook_url.rstrip("/") + "/api/v1/alert", headers=headers, json=body,
                         verify=verify, timeout=int(options.get("timeout", 10)))
    if resp.status_code in (200, 201):
        log(f"alert {body['sourceRef']} created in TheHive ({resp.json().get('_id')})")
    else:
        log(f"TheHive returned HTTP {resp.status_code} for {body['sourceRef']}: {resp.text[:500]}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as exc:
        log(f"unhandled error: {exc!r}")
        sys.exit(1)
