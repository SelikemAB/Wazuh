#!/usr/bin/env python3
"""Helper used by the shell scripts in this directory.

Sub-commands
  init-env                 create .env from .env.example with random secrets
  get KEY                  print a value from .env
  validate                 check every credential in .env against the policy
  render                   render config templates (needs *_HASH env vars)
  api-set-passwords        set the Wazuh API users' passwords from .env
  api-create-shuffle-user  create the least-privilege API user for Shuffle

Only the Python standard library is used so it runs on any Docker host.
"""
import base64
import json
import os
import re
import secrets
import ssl
import string
import sys
import urllib.error
import urllib.request
import uuid
from xml.sax.saxutils import escape

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(ROOT, ".env")
ENV_EXAMPLE = os.path.join(ROOT, ".env.example")

# Symbols accepted in passwords. `$`, quotes, backslash, backtick, `#`, `&`
# and whitespace are excluded because they break docker compose variable
# interpolation, YAML or shell quoting somewhere in the pipeline.
PASSWORD_SYMBOLS = ".*+?-_@=^~%,:"
PASSWORD_RE = re.compile(r"^[A-Za-z0-9" + re.escape(PASSWORD_SYMBOLS) + r"]{12,64}$")
# Wazuh's password tooling requires at least one of these specific symbols.
REQUIRED_SYMBOLS = ".*+?-"

# .env keys that are passwords and must satisfy the Wazuh password policy
# (8-64 chars, upper, lower, digit, symbol; we require 12+).
POLICY_PASSWORDS = [
    "INDEXER_ADMIN_PASSWORD",
    "DASHBOARD_KIBANASERVER_PASSWORD",
    "API_ADMIN_PASSWORD",
    "API_WUI_PASSWORD",
    "ENROLLMENT_PASSWORD",
]

# Values that must never survive into a real deployment.
KNOWN_DEFAULTS = {
    "admin", "SecretPassword", "kibanaserver", "wazuh", "MyS3cr37P450r.*-",
    "wazuh-wui", "secret", "changeme",
}


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------- .env
def parse_env(path=ENV_FILE):
    if not os.path.exists(path):
        die(f"{path} not found - run scripts/init-env.sh first")
    env = {}
    with open(path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            env[key.strip()] = value
    return env


def env_bool(env, key):
    return env.get(key, "false").strip().lower() in ("1", "true", "yes", "on")


def gen_password(length=24):
    alphabet = string.ascii_letters + string.digits + ".-+@="
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if check_password(pw) is None:
            return pw


def check_password(pw):
    if not PASSWORD_RE.match(pw):
        return f"12-64 chars, only letters, digits and {PASSWORD_SYMBOLS}"
    if not re.search(r"[a-z]", pw):
        return "needs a lowercase letter"
    if not re.search(r"[A-Z]", pw):
        return "needs an uppercase letter"
    if not re.search(r"[0-9]", pw):
        return "needs a digit"
    if not any(c in REQUIRED_SYMBOLS for c in pw):
        return f"needs one symbol from {REQUIRED_SYMBOLS}"
    if pw in KNOWN_DEFAULTS or "changeme" in pw.lower():
        return "is a default / placeholder value"
    return None


def shuffle_host_ok(host):
    return bool(host) and host not in ("localhost", "127.0.0.1", "::1", "0.0.0.0")


def cmd_init_env():
    if os.path.exists(ENV_FILE):
        die(".env already exists - edit it or delete it first")
    generators = {
        "__GENERATE__": gen_password,
        "__GENERATE_HEX32__": lambda: secrets.token_hex(16),
        "__GENERATE_KEY40__": lambda: "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(40)),
        "__GENERATE_SECRET__": lambda: secrets.token_urlsafe(48),
        "__GENERATE_UUID__": lambda: str(uuid.uuid4()),
    }
    out = []
    with open(ENV_EXAMPLE) as fh:
        for line in fh:
            for token, gen in generators.items():
                while token in line:
                    line = line.replace(token, gen(), 1)
            out.append(line)
    old_umask = os.umask(0o077)
    try:
        with open(ENV_FILE, "w") as fh:
            fh.writelines(out)
    finally:
        os.umask(old_umask)
    print(f"Created {ENV_FILE} (mode 600) with freshly generated secrets.")


def cmd_get(key):
    print(parse_env().get(key, ""))


def cmd_validate():
    env = parse_env()
    errors = []
    for key in POLICY_PASSWORDS:
        value = env.get(key, "")
        problem = check_password(value) if value else "is empty"
        if problem:
            errors.append(f"{key} {problem}")
    if len(set(env.get(k) for k in POLICY_PASSWORDS)) != len(POLICY_PASSWORDS):
        errors.append("every password in POLICY_PASSWORDS must be unique")
    if env.get("API_WUI_USERNAME", "wazuh-wui") == "wazuh":
        errors.append("API_WUI_USERNAME must not be the 'wazuh' admin user")
    if not re.fullmatch(r"[0-9a-f]{32}", env.get("WAZUH_CLUSTER_KEY", "")):
        errors.append("WAZUH_CLUSTER_KEY must be 32 hex characters")
    if env_bool(env, "ENABLE_MISP") and not env.get("MISP_API_KEY"):
        errors.append("ENABLE_MISP=true but MISP_API_KEY is empty")
    if env_bool(env, "ENABLE_THEHIVE") and not env.get("THEHIVE_API_KEY"):
        errors.append("ENABLE_THEHIVE=true but THEHIVE_API_KEY is empty")
    if env_bool(env, "ENABLE_SOAR_STACK"):
        for key in ("MISP_ADMIN_PASSWORD", "MISP_DB_PASSWORD", "MISP_DB_ROOT_PASSWORD",
                    "MISP_REDIS_PASSWORD", "THEHIVE_SECRET", "CORTEX_SECRET"):
            v = env.get(key, "")
            if not v or "changeme" in v.lower() or "__GENERATE" in v:
                errors.append(f"{key} must be set when ENABLE_SOAR_STACK=true")
        if not re.fullmatch(r"[A-Za-z0-9]{40}", env.get("MISP_ADMIN_KEY", "")):
            errors.append("MISP_ADMIN_KEY must be 40 alphanumeric characters")
    if env_bool(env, "ENABLE_SHUFFLE_STACK"):
        for key in ("SHUFFLE_OPENSEARCH_PASSWORD", "SHUFFLE_ADMIN_PASSWORD"):
            problem = check_password(env.get(key, "")) if env.get(key) else "is empty"
            if problem:
                errors.append(f"{key} {problem}")
        if not re.fullmatch(r"[0-9a-f-]{36}", env.get("SHUFFLE_ADMIN_APIKEY", "")):
            errors.append("SHUFFLE_ADMIN_APIKEY must be a UUID")
        if len(env.get("SHUFFLE_ENCRYPTION_MODIFIER", "")) < 32:
            errors.append("SHUFFLE_ENCRYPTION_MODIFIER must be at least 32 characters")
        if not shuffle_host_ok(env.get("SOAR_HOST_ADDRESS", "")):
            errors.append("SOAR_HOST_ADDRESS must be the Docker host's LAN IP/FQDN (not empty/localhost)")
    if env_bool(env, "ENABLE_SHUFFLE"):
        urls = [u for u in env.get("SHUFFLE_WEBHOOK_URLS", "").split(",") if u.strip()]
        if not urls:
            errors.append("ENABLE_SHUFFLE=true but SHUFFLE_WEBHOOK_URLS is empty")
        for u in urls:
            if not re.match(r"^https?://[^\s]+/api/v1/hooks/webhook_[0-9a-f-]+$", u.strip()):
                errors.append(f"SHUFFLE_WEBHOOK_URLS entry is not a Shuffle webhook URL: {u}")
        level = env.get("SHUFFLE_MIN_LEVEL", "")
        if level and not (level.isdigit() and 0 <= int(level) <= 16):
            errors.append("SHUFFLE_MIN_LEVEL must be empty or 0-16")
    if errors:
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        die("credential policy check failed (see above)")
    print("Credential policy check passed.")


# ------------------------------------------------------------------------ render
def substitute(template, values, path):
    def repl(match):
        key = match.group(1)
        if key not in values:
            die(f"{path}: no value for placeholder {key}")
        return values[key]
    return re.sub(r"\$\{([A-Z0-9_]+)\}", repl, template)


def write_in_place(path, content, mode=0o640):
    # Truncate + write (never rename) so single-file bind mounts in running
    # containers keep pointing at the same inode and see the new content.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    os.chmod(path, mode)


def integration_blocks(env):
    blocks = []
    if env_bool(env, "ENABLE_MISP"):
        opts = json.dumps({
            "verify_ssl": env_bool(env, "MISP_VERIFY_SSL"),
            "timeout": int(env.get("MISP_TIMEOUT", "10")),
        })
        blocks.append(f"""  <!-- MISP: IoC lookup for every alert in the listed rule groups -->
  <integration>
    <name>custom-misp</name>
    <hook_url>{escape(env.get("MISP_URL", "https://misp-core"))}</hook_url>
    <api_key>{escape(env["MISP_API_KEY"])}</api_key>
    <group>{escape(env.get("MISP_RULE_GROUPS", "sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck"))}</group>
    <alert_format>json</alert_format>
    <options>{escape(opts)}</options>
  </integration>""")
    if env_bool(env, "ENABLE_THEHIVE"):
        opts = json.dumps({
            "verify_ssl": env_bool(env, "THEHIVE_VERIFY_SSL"),
            "timeout": int(env.get("THEHIVE_TIMEOUT", "10")),
            "tlp": int(env.get("THEHIVE_TLP", "2")),
            "pap": int(env.get("THEHIVE_PAP", "2")),
        })
        blocks.append(f"""  <!-- TheHive: forward alerts at or above the level threshold -->
  <integration>
    <name>custom-thehive</name>
    <hook_url>{escape(env.get("THEHIVE_URL", "http://thehive:9000"))}</hook_url>
    <api_key>{escape(env["THEHIVE_API_KEY"])}</api_key>
    <level>{int(env.get("THEHIVE_MIN_LEVEL", "7"))}</level>
    <alert_format>json</alert_format>
    <options>{escape(opts)}</options>
  </integration>""")
    if env_bool(env, "ENABLE_SHUFFLE"):
        # Built-in Wazuh integration (integrations/shuffle.py): posts every
        # alert to the webhook. One block per webhook URL.
        level = env.get("SHUFFLE_MIN_LEVEL", "").strip()
        level_tag = f"\n    <level>{int(level)}</level>" if level else ""
        for url in [u.strip() for u in env.get("SHUFFLE_WEBHOOK_URLS", "").split(",") if u.strip()]:
            blocks.append(f"""  <!-- Shuffle: {"all alerts" if not level else "alerts >= level " + level} -->
  <integration>
    <name>shuffle</name>
    <hook_url>{escape(url)}</hook_url>{level_tag}
    <alert_format>json</alert_format>
  </integration>""")
    return "\n\n".join(blocks) if blocks else "  <!-- no integrations enabled -->"


def cmd_render():
    env = parse_env()
    for key in ("INDEXER_ADMIN_HASH", "DASHBOARD_KIBANASERVER_HASH"):
        if not os.environ.get(key, "").startswith("$2"):
            die(f"{key} (bcrypt hash) must be exported by the caller")

    agent_ca = ""
    if env_bool(env, "AGENT_CERT_VERIFICATION"):
        agent_ca = "    <ssl_agent_ca>etc/agent-ca/rootCA.pem</ssl_agent_ca>"

    values = {
        "INDEXER_ADMIN_HASH": os.environ["INDEXER_ADMIN_HASH"],
        "DASHBOARD_KIBANASERVER_HASH": os.environ["DASHBOARD_KIBANASERVER_HASH"],
        "API_WUI_USERNAME": env.get("API_WUI_USERNAME", "wazuh-wui"),
        "API_WUI_PASSWORD": env["API_WUI_PASSWORD"],
        "WAZUH_CLUSTER_KEY": env["WAZUH_CLUSTER_KEY"],
        "WAZUH_AUTH_SSL_AGENT_CA": agent_ca,
        "WAZUH_INTEGRATIONS": integration_blocks(env),
    }
    targets = [
        ("config/wazuh_indexer/internal_users.yml.tpl", "config/wazuh_indexer/internal_users.yml", 0o644),
        ("config/wazuh_dashboard/wazuh.yml.tpl", "config/wazuh_dashboard/wazuh.yml", 0o644),
        ("config/wazuh_cluster/wazuh_manager.conf.tpl", "config/wazuh_cluster/wazuh_manager.conf", 0o644),
    ]
    for src, dst, mode in targets:
        with open(os.path.join(ROOT, src)) as fh:
            rendered = substitute(fh.read(), values, src)
        write_in_place(os.path.join(ROOT, dst), rendered, mode)
        print(f"  rendered {dst}")


# ------------------------------------------------------------------- Wazuh API
class WazuhAPI:
    def __init__(self, url):
        self.url = url.rstrip("/")
        # The API uses a self-signed certificate generated inside the manager.
        # We only ever talk to it over localhost from the Docker host.
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.token = None

    def _request(self, method, path, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        with urllib.request.urlopen(req, context=self.ctx, timeout=30) as resp:
            return json.loads(resp.read() or b"{}")

    def login(self, user, password):
        basic = base64.b64encode(f"{user}:{password}".encode()).decode()
        try:
            res = self._request("POST", "/security/user/authenticate",
                                headers={"Authorization": f"Basic {basic}"})
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                return False
            raise
        self.token = res["data"]["token"]
        return True

    def user_id(self, username):
        res = self._request("GET", "/security/users?limit=500")
        for item in res["data"]["affected_items"]:
            if item["username"] == username:
                return item["id"]
        die(f"Wazuh API user '{username}' not found")

    def set_password(self, username, password):
        uid = self.user_id(username)
        res = self._request("PUT", f"/security/users/{uid}", {"password": password})
        if res.get("error"):
            die(f"changing password of '{username}' failed: {json.dumps(res)}")


def cmd_api_set_passwords():
    """Make the 'wazuh' and wazuh-wui API users match .env.

    The current 'wazuh' password is tried in this order: the .env value
    (already rotated), $CURRENT_API_ADMIN_PASSWORD, the factory default.
    """
    env = parse_env()
    api = WazuhAPI(os.environ.get("WAZUH_API_URL", "https://127.0.0.1:55000"))
    new_admin = env["API_ADMIN_PASSWORD"]
    candidates = [new_admin, os.environ.get("CURRENT_API_ADMIN_PASSWORD"), "wazuh"]
    current = next((c for c in candidates if c and api.login("wazuh", c)), None)
    if current is None:
        die("cannot log in as API user 'wazuh' - export CURRENT_API_ADMIN_PASSWORD=<current> and retry")

    if current != new_admin:
        api.set_password("wazuh", new_admin)
        print("  API user 'wazuh'      : password changed")
        api.login("wazuh", new_admin)
    else:
        print("  API user 'wazuh'      : already matches .env")

    wui = env.get("API_WUI_USERNAME", "wazuh-wui")
    api.set_password(wui, env["API_WUI_PASSWORD"])
    print(f"  API user '{wui}' : password set from .env")

    check = WazuhAPI(api.url)
    for user, pw in (("wazuh", new_admin), (wui, env["API_WUI_PASSWORD"])):
        if not check.login(user, pw):
            die(f"verification login failed for API user '{user}'")
    print("  verified: both API users authenticate with the new passwords")


def cmd_api_create_shuffle_user():
    """Create/refresh a least-privilege API user that may only run active responses."""
    env = parse_env()
    user = env.get("SHUFFLE_WAZUH_API_USER", "shuffle-ar")
    password = env.get("SHUFFLE_WAZUH_API_PASSWORD", "")
    problem = check_password(password) if password else "is empty"
    if problem:
        die(f"SHUFFLE_WAZUH_API_PASSWORD {problem}")
    api = WazuhAPI(os.environ.get("WAZUH_API_URL", "https://127.0.0.1:55000"))
    if not api.login("wazuh", env["API_ADMIN_PASSWORD"]):
        die("cannot log in as API user 'wazuh' with API_ADMIN_PASSWORD")

    def find(path, key, name):
        res = api._request("GET", f"{path}?limit=500")
        for item in res["data"]["affected_items"]:
            if item.get(key) == name:
                return item["id"]
        return None

    policy_name, role_name = "shuffle_active_response", "shuffle_active_response"
    policy = {"actions": ["active-response:command"], "resources": ["agent:id:*"], "effect": "allow"}
    pid = find("/security/policies", "name", policy_name)
    if pid is None:
        pid = api._request("POST", "/security/policies",
                           {"name": policy_name, "policy": policy})["data"]["affected_items"][0]["id"]
    rid = find("/security/roles", "name", role_name)
    if rid is None:
        rid = api._request("POST", "/security/roles", {"name": role_name})["data"]["affected_items"][0]["id"]
    api._request("POST", f"/security/roles/{rid}/policies?policy_ids={pid}")
    uid = find("/security/users", "username", user)
    if uid is None:
        uid = api._request("POST", "/security/users",
                           {"username": user, "password": password})["data"]["affected_items"][0]["id"]
        print(f"  created API user '{user}'")
    else:
        api._request("PUT", f"/security/users/{uid}", {"password": password})
        print(f"  API user '{user}' exists - password synced from .env")
    api._request("POST", f"/security/users/{uid}/roles?role_ids={rid}")
    if not WazuhAPI(api.url).login(user, password):
        die(f"verification login failed for '{user}'")
    print(f"  '{user}' can only run active-response commands (role {role_name})")


def main(argv):
    if not argv:
        die(__doc__)
    cmd, args = argv[0], argv[1:]
    if cmd == "init-env":
        cmd_init_env()
    elif cmd == "get" and len(args) == 1:
        cmd_get(args[0])
    elif cmd == "validate":
        cmd_validate()
    elif cmd == "render":
        cmd_render()
    elif cmd == "api-set-passwords":
        cmd_api_set_passwords()
    elif cmd == "api-create-shuffle-user":
        cmd_api_create_shuffle_user()
    else:
        die(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
