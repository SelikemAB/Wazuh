#!/usr/bin/env python3
"""Build and import the starter Shuffle workflows.

  shuffle_workflows.py build              write importable JSON files
  shuffle_workflows.py import [--write-env]
                                          create/update the workflows in Shuffle,
                                          start their webhooks and (optionally)
                                          put the webhook URLs into .env

Each workflow = Webhook trigger -> "Shuffle Tools / Execute python" steps whose
code lives in integrations/shuffle/code/ (with _common.py prepended).
IDs are deterministic (uuid5), so re-importing updates the same workflow and
keeps the webhook URL stable.

Outputs
  integrations/shuffle/workflows/<slug>.json   secrets blank (safe to commit / UI import)
  secrets/shuffle/<slug>.json                  variables filled from .env (git-ignored)
"""
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wazuhctl  # noqa: E402

ROOT = wazuhctl.ROOT
CODE_DIR = os.path.join(ROOT, "integrations", "shuffle", "code")
PUBLIC_DIR = os.path.join(ROOT, "integrations", "shuffle", "workflows")
SECRET_DIR = os.path.join(ROOT, "secrets", "shuffle")
NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/wazuh-docker-boilerplate/shuffle")
TOOLS_APP, TOOLS_VERSION = "Shuffle Tools", "1.2.0"
ENVIRONMENT = "Shuffle"


def sid(*parts):
    return str(uuid.uuid5(NS, "/".join(parts)))


# --------------------------------------------------------------------- spec
def host(env):
    return env.get("SOAR_HOST_ADDRESS", "") or "SOAR_HOST_ADDRESS"


def variables(env):
    """name -> (value, secret?) for every workflow variable used in the code."""
    h = host(env)
    return {
        "misp_url": (env.get("SHUFFLE_MISP_URL") or f"https://{h}:{env.get('MISP_PORT', '8443')}", False),
        "misp_api_key": (env.get("MISP_API_KEY", ""), True),
        "thehive_url": (env.get("SHUFFLE_THEHIVE_URL") or f"http://{h}:{env.get('THEHIVE_PORT', '9000')}", False),
        "thehive_api_key": (env.get("THEHIVE_API_KEY", ""), True),
        "thehive_organisation": (env.get("SHUFFLE_THEHIVE_ORGANISATION", ""), False),
        "thehive_min_level": (env.get("SHUFFLE_THEHIVE_MIN_LEVEL", "10"), False),
        "case_min_level": (env.get("SHUFFLE_CASE_MIN_LEVEL", "12"), False),
        "cortex_url": (env.get("SHUFFLE_CORTEX_URL") or f"http://{h}:{env.get('CORTEX_PORT', '9001')}", False),
        "cortex_api_key": (env.get("SHUFFLE_CORTEX_API_KEY", ""), True),
        "cortex_analyzers": (env.get("SHUFFLE_CORTEX_ANALYZERS", "MISP_2_1,AbuseIPDB_1_0"), False),
        "verify_ssl": (env.get("SHUFFLE_VERIFY_SSL", "false"), False),
        "wazuh_api_url": (env.get("SHUFFLE_WAZUH_API_URL") or f"https://{h}:55000", False),
        "wazuh_api_user": (env.get("SHUFFLE_WAZUH_API_USER", "shuffle-ar"), False),
        "wazuh_api_password": (env.get("SHUFFLE_WAZUH_API_PASSWORD", ""), True),
        "ar_rule_ids": (env.get("SHUFFLE_AR_RULE_IDS", "5712,5720,5763,5551,60204,31151,100623,100624"), False),
        "ar_allowlist": (env.get("SHUFFLE_AR_ALLOWLIST", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8"), False),
        "ar_command": (env.get("SHUFFLE_AR_COMMAND", "!firewall-drop"), False),
        "notify_min_level": (env.get("SHUFFLE_NOTIFY_MIN_LEVEL", "12"), False),
        "slack_webhook_url": (env.get("SHUFFLE_SLACK_WEBHOOK_URL", ""), True),
        "teams_webhook_url": (env.get("SHUFFLE_TEAMS_WEBHOOK_URL", ""), True),
        "smtp_host": (env.get("SHUFFLE_SMTP_HOST", ""), False),
        "smtp_port": (env.get("SHUFFLE_SMTP_PORT", "587"), False),
        "smtp_user": (env.get("SHUFFLE_SMTP_USER", ""), False),
        "smtp_password": (env.get("SHUFFLE_SMTP_PASSWORD", ""), True),
        "mail_from": (env.get("SHUFFLE_MAIL_FROM", ""), False),
        "mail_to": (env.get("SHUFFLE_MAIL_TO", ""), False),
        "dashboard_url": (f"https://{h}:{env.get('DASHBOARD_PORT', '443')}", False),
    }


WORKFLOWS = [
    {
        "slug": "wazuh-enrich-thehive",
        "name": "Wazuh - Enrich & TheHive case",
        "description": "Wazuh alert -> MISP lookup -> TheHive alert (+case when severe or MISP hit) -> Cortex analyzers -> case comment.",
        "steps": ["enrich_extract", "enrich_misp", "enrich_thehive", "enrich_cortex"],
        "gate": "enrich_extract",
    },
    {
        "slug": "wazuh-active-response",
        "name": "Wazuh - Auto-response (block IP)",
        "description": "Brute-force / MISP-IP alerts -> allowlist check -> Wazuh active response firewall-drop on the reporting agent.",
        "steps": ["ar_decide", "ar_block"],
        "gate": "ar_decide",
    },
    {
        "slug": "wazuh-notify",
        "name": "Wazuh - Notification",
        "description": "High-severity Wazuh alerts -> Slack / Microsoft Teams / e-mail summary.",
        "steps": ["notify_filter", "notify_send"],
        "gate": "notify_filter",
    },
]


def webhook_path(wf):
    return "/api/v1/hooks/webhook_" + sid(wf["slug"], "trigger")


def step_code(step):
    with open(os.path.join(CODE_DIR, "_common.py")) as fh:
        common = fh.read()
    with open(os.path.join(CODE_DIR, step + ".py")) as fh:
        return common + "\n\n" + fh.read()


def used_vars(code, all_vars):
    names = set(re.findall(r"\$([a-z_]+)", code))
    return [n for n in all_vars if n in names]


def param(name, value, multiline=False):
    return {"name": name, "value": value, "multiline": multiline, "required": True,
            "variant": "STATIC_VALUE", "action_field": "", "id": "", "description": ""}


def build(wf, env, fill_secrets):
    all_vars = variables(env)
    actions, branches, needed = [], [], []
    for i, step in enumerate(wf["steps"]):
        code = step_code(step)
        needed += [v for v in used_vars(code, all_vars) if v not in needed]
        actions.append({
            "app_name": TOOLS_APP, "app_version": TOOLS_VERSION, "app_id": "",
            "name": "execute_python", "label": step, "id": sid(wf["slug"], step),
            "environment": ENVIRONMENT, "is_valid": True, "isStartNode": i == 0,
            "errors": [], "authentication_id": "", "sharing": False, "private_id": "",
            "parameters": [param("code", code, multiline=True)],
            "position": {"x": 400 + 320 * i, "y": 300},
        })
        if i > 0:
            branch = {"id": sid(wf["slug"], "branch", step), "source_id": actions[i - 1]["id"],
                      "destination_id": actions[i]["id"], "conditions": [], "label": "", "has_errors": False}
            if wf["steps"][i - 1] == wf["gate"]:
                branch["conditions"] = [{
                    "condition": {"name": "condition", "value": "equals", "id": sid(wf["slug"], "cond")},
                    "source": {"name": "source", "value": "$%s.message.proceed" % wf["gate"],
                               "variant": "STATIC_VALUE", "action_field": "", "id": sid(wf["slug"], "src")},
                    "destination": {"name": "destination", "value": "true",
                                    "variant": "STATIC_VALUE", "action_field": "", "id": sid(wf["slug"], "dst")},
                }]
            branches.append(branch)

    trigger_id = sid(wf["slug"], "trigger")
    backend = "http://shuffle-backend:5001"
    trigger = {
        "app_name": "Webhook", "app_version": "1.0.0", "name": "Webhook", "label": "wazuh_alerts",
        "description": "Receives Wazuh alerts from the built-in shuffle integration",
        "id": trigger_id, "trigger_type": "WEBHOOK", "status": "uninitialized",
        "environment": ENVIRONMENT, "is_valid": True, "errors": [], "large_image": "",
        "position": {"x": 100, "y": 300},
        "parameters": [param("url", backend + webhook_path(wf)), param("tmp", ""),
                       param("auth_headers", ""), param("custom_response_body", ""),
                       param("await_response", "v1")],
    }
    branches.insert(0, {"id": sid(wf["slug"], "branch", "trigger"), "source_id": trigger_id,
                        "destination_id": actions[0]["id"], "conditions": [], "label": "", "has_errors": False})
    wvars = []
    for name in needed:
        value, secret = all_vars[name]
        wvars.append({"id": sid(wf["slug"], "var", name), "name": name,
                      "value": value if (fill_secrets or not secret) else "",
                      "description": "secret - fill in after import" if secret else ""})
    return {
        "id": sid(wf["slug"]), "name": wf["name"], "description": wf["description"],
        "is_valid": True, "start": actions[0]["id"], "actions": actions, "branches": branches,
        "triggers": [trigger], "workflow_variables": wvars, "execution_variables": [],
        "tags": ["wazuh", "boilerplate"], "errors": [], "sharing": "private",
        "execution_environment": ENVIRONMENT,
        "configuration": {"exit_on_error": False, "start_from_top": False},
    }


def write_json(path, obj, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    os.chmod(path, mode)


def cmd_build(env):
    for wf in WORKFLOWS:
        write_json(os.path.join(PUBLIC_DIR, wf["slug"] + ".json"), build(wf, {}, fill_secrets=False))
        if env:
            write_json(os.path.join(SECRET_DIR, wf["slug"] + ".json"), build(wf, env, fill_secrets=True), 0o600)
    print(f"  public workflows (no secrets): {os.path.relpath(PUBLIC_DIR, ROOT)}/")
    if env:
        print(f"  filled workflows (secrets)   : {os.path.relpath(SECRET_DIR, ROOT)}/ (mode 600)")


# ------------------------------------------------------------------ import
class Shuffle:
    def __init__(self, url, apikey):
        self.url, self.apikey = url.rstrip("/"), apikey
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def call(self, method, path, body=None):
        req = urllib.request.Request(self.url + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        req.add_header("Authorization", "Bearer " + self.apikey)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=60) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"{method} {path}: HTTP {exc.code} {exc.read()[:300]!r}") from None
        return json.loads(raw) if raw else {}


def update_env(key, value):
    path = wazuhctl.ENV_FILE
    with open(path) as fh:
        lines = fh.readlines()
    for i, line in enumerate(lines):
        if line.startswith(key + "="):
            lines[i] = f"{key}={value}\n"
            break
    else:
        lines.append(f"{key}={value}\n")
    with open(path, "w") as fh:
        fh.writelines(lines)


def cmd_import(env, write_env):
    api = Shuffle(os.environ.get("SHUFFLE_API_URL", "http://127.0.0.1:5001"), env["SHUFFLE_ADMIN_APIKEY"])
    existing = {w.get("name"): w.get("id") for w in api.call("GET", "/api/v1/workflows") or []}
    hook_urls, manual = [], []
    for wf in WORKFLOWS:
        body = build(wf, env, fill_secrets=True)
        wf_id = existing.get(body["name"])
        if not wf_id:
            created = api.call("POST", "/api/v1/workflows",
                               {"name": body["name"], "description": body["description"]})
            wf_id = created.get("id")
        body["id"] = wf_id
        api.call("PUT", f"/api/v1/workflows/{wf_id}", body)
        trigger = body["triggers"][0]
        try:
            api.call("POST", "/api/v1/hooks/new", {
                "name": trigger["label"], "type": "webhook", "id": trigger["id"], "workflow": wf_id,
                "start": body["start"], "environment": "onprem", "auth": "",
                "custom_response": "", "version": "v1"})
        except RuntimeError as exc:
            if "exist" not in str(exc).lower():
                manual.append(f"{body['name']}: {exc}")
        hook_urls.append("http://shuffle-backend:5001" + webhook_path(wf))
        print(f"  imported '{body['name']}' (id {wf_id})")
    print("\n  Webhook URLs (reachable by wazuh.manager):")
    for url in hook_urls:
        print("    " + url)
    if manual:
        print("\n  Could not start these webhooks through the API. Open the workflow in")
        print("  Shuffle, click the Webhook node and press 'Start':")
        for m in manual:
            print("    - " + m)
    if write_env:
        update_env("SHUFFLE_WEBHOOK_URLS", ",".join(hook_urls))
        update_env("ENABLE_SHUFFLE", "true")
        print("\n  .env updated: ENABLE_SHUFFLE=true, SHUFFLE_WEBHOOK_URLS set")


def main(argv):
    if not argv or argv[0] not in ("build", "import"):
        wazuhctl.die(__doc__)
    env = wazuhctl.parse_env() if os.path.exists(wazuhctl.ENV_FILE) else {}
    if argv[0] == "build":
        cmd_build(env)
    else:
        if not env:
            wazuhctl.die(".env missing")
        cmd_build(env)
        cmd_import(env, "--write-env" in argv)


if __name__ == "__main__":
    main(sys.argv[1:])
