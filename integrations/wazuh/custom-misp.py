#!/usr/bin/env python3
"""Wazuh -> MISP IoC enrichment.

Called by wazuh-integratord for every alert that matches the <group> list of
the `custom-misp` <integration> block:

    custom-misp <alert_file> <api_key> <hook_url> [<...options>]

Indicators (hashes, public IPs, domains) are extracted from the alert and
looked up with MISP's /attributes/restSearch. Each hit is written back to the
Wazuh analysis queue as a JSON event with "integration": "misp", which the
rules in config/wazuh_rules/misp_rules.xml turn into alerts (100620-100629).
"""
import ipaddress
import json
import os
import socket
import sys
import time

try:
    import requests
    import urllib3
except ImportError:  # pragma: no cover - always present in Wazuh's python
    print("requests module missing", file=sys.stderr)
    sys.exit(1)

WAZUH_PATH = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SOCKET_ADDR = os.path.join(WAZUH_PATH, "queue", "sockets", "queue")
LOG_FILE = os.path.join(WAZUH_PATH, "logs", "integrations.log")
INTEGRATION = "misp"
MAX_IOCS = 10


def log(msg):
    with open(LOG_FILE, "a") as fh:
        fh.write(f"{time.strftime('%Y/%m/%d %H:%M:%S')} custom-misp: {msg}\n")


def load_options(args):
    # integratord passes the path of a JSON file whose name ends in "options"
    for arg in args[4:]:
        if arg.endswith("options"):
            try:
                with open(arg) as fh:
                    return json.load(fh)
            except (OSError, ValueError) as exc:
                log(f"cannot read options file {arg}: {exc}")
    return {}


def is_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global


def parse_sysmon_hashes(raw):
    """'SHA1=..,MD5=..,SHA256=..,IMPHASH=..' -> {'sha256': ..., ...}"""
    out = {}
    for part in (raw or "").split(","):
        if "=" in part:
            algo, _, value = part.partition("=")
            out[algo.strip().lower()] = value.strip().lower()
    return out


def extract_iocs(alert):
    """Return a de-duplicated list of (ioc_type, value)."""
    iocs = []
    data = alert.get("data", {})
    win = data.get("win", {}).get("eventdata", {})
    groups = alert.get("rule", {}).get("groups", [])

    # Sysmon: process create (1), driver/image load (6/7), file stream (15)
    hashes = parse_sysmon_hashes(win.get("hashes") or win.get("hash"))
    for algo in ("sha256", "md5", "sha1"):
        if hashes.get(algo):
            iocs.append((algo, hashes[algo]))
            break
    # Sysmon 3: network connection
    for key in ("destinationIp", "sourceIp"):
        if is_public_ip(win.get(key, "")):
            iocs.append(("ip", win[key]))
    # Sysmon 22: DNS query
    if win.get("queryName"):
        iocs.append(("domain", win["queryName"].rstrip(".").lower()))

    # File integrity monitoring
    if "syscheck" in groups or "syscheck" in alert:
        sc = alert.get("syscheck", {})
        for algo in ("sha256_after", "md5_after", "sha1_after"):
            if sc.get(algo):
                iocs.append((algo.split("_")[0], sc[algo].lower()))
                break

    # Generic decoders (firewall, web, sshd, ...)
    for key in ("srcip", "dstip"):
        if is_public_ip(data.get(key, "")):
            iocs.append(("ip", data[key]))

    seen, unique = set(), []
    for ioc in iocs:
        if ioc[1] not in seen:
            seen.add(ioc[1])
            unique.append(ioc)
    return unique[:MAX_IOCS]


def misp_lookup(base_url, api_key, value, verify, timeout):
    url = base_url.rstrip("/") + "/attributes/restSearch"
    headers = {
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    body = {"returnFormat": "json", "value": value, "limit": 5, "includeEventTags": 1}
    resp = requests.post(url, headers=headers, json=body, verify=verify, timeout=timeout)
    resp.raise_for_status()
    return resp.json().get("response", {}).get("Attribute", [])


def send_event(msg, agent):
    """Push a JSON event into the analysis queue, keeping the agent context."""
    if not agent or agent.get("id") == "000":
        location = INTEGRATION
    else:
        location = "[{0}] ({1}) {2}->{3}".format(
            agent.get("id"), agent.get("name"), agent.get("ip", "any"), INTEGRATION)
    payload = f"1:{location}:{json.dumps(msg)}"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.connect(SOCKET_ADDR)
        sock.send(payload.encode())
    finally:
        sock.close()


def main(args):
    if len(args) < 4:
        log(f"wrong arguments: {args}")
        sys.exit(2)
    alert_file, api_key, hook_url = args[1], args[2], args[3]
    options = load_options(args)
    verify = bool(options.get("verify_ssl", True))
    timeout = int(options.get("timeout", 10))
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    with open(alert_file) as fh:
        alert = json.load(fh)

    rule = alert.get("rule", {})
    # Never re-process our own output (avoids feedback loops)
    if INTEGRATION in rule.get("groups", []):
        return

    source = {
        "alert_id": alert.get("id"),
        "rule": rule.get("id"),
        "description": rule.get("description"),
        "level": rule.get("level"),
    }
    agent = alert.get("agent", {})

    for ioc_type, value in extract_iocs(alert):
        try:
            attributes = misp_lookup(hook_url, api_key, value, verify, timeout)
        except requests.RequestException as exc:
            log(f"lookup of {value} failed: {exc}")
            send_event({"integration": INTEGRATION, "misp": {
                "found": 0, "error": str(exc)[:500], "value": value}, "source": source}, agent)
            return

        if not attributes:
            continue
        attr = attributes[0]
        event = attr.get("Event", {})
        tags = [t.get("name") for t in attr.get("Tag", []) + event.get("Tag", []) if t.get("name")]
        send_event({
            "integration": INTEGRATION,
            "misp": {
                "found": 1,
                "hits": len(attributes),
                "ioc_type": ioc_type,
                "value": attr.get("value", value),
                "type": attr.get("type"),
                "category": attr.get("category"),
                "to_ids": attr.get("to_ids"),
                "comment": attr.get("comment"),
                "event_id": attr.get("event_id"),
                "event_uuid": event.get("uuid"),
                "event_info": event.get("info"),
                "threat_level_id": event.get("threat_level_id"),
                "tags": tags[:20],
            },
            "source": source,
        }, agent)
        log(f"MISP hit for {ioc_type}={value} (event {attr.get('event_id')})")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as exc:  # integratord only sees the exit code
        log(f"unhandled error: {exc!r}")
        sys.exit(1)
