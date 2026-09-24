# 2. Secure agent enrollment (enrollment key)

By default `wazuh-authd` (TCP 1515) enrolls **any** host that connects. Anyone
who can reach the port can then register fake agents, fill `client.keys`, or
take over the name of an agent. This deployment turns on password
enrollment: an agent is only registered when it presents the enrollment key.
Agent client certificates can be required as a second factor.

```
 agent                                  wazuh.manager
 ─────                                  ─────────────
 1. TLS to :1515  ───────────────────▶  wazuh-authd
    sends: enrollment key (authd.pass)   ├─ checks the key          (use_password=yes)
    [+ client cert sslagent.cert]        ├─ checks cert vs agent CA (ssl_agent_ca, optional)
                                         └─ returns the agent's own key → client.keys
 2. events to :1514 (AES, per-agent key) ▶ wazuh-remoted
```

The enrollment key is only used to register. After that the agent
authenticates with its own key in `client.keys`, so rotating the enrollment
key does not disconnect agents that are already enrolled.

---

## Part A: Manager side

### A.1 Automated (done by `setup.sh`)

```bash
./scripts/enable-enrollment.sh
```

The script:

1. Writes `ENROLLMENT_PASSWORD` from `.env` to `secrets/authd.pass` (mode 600).
2. Installs it in the container as `/var/ossec/etc/authd.pass` (`root:wazuh 640`).
3. Checks that the rendered `ossec.conf` contains `<use_password>yes</use_password>`.
4. Installs the agent CA and the CA-signed manager certificate if you created them.
5. Restarts the manager and confirms that `wazuh-authd` loaded the key.

The `<auth>` block that gets rendered (`config/wazuh_cluster/wazuh_manager.conf.tpl`):

```xml
<auth>
  <disabled>no</disabled>
  <port>1515</port>
  <use_password>yes</use_password>                 <!-- enrollment key required -->
  <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
  <!-- <ssl_agent_ca>etc/agent-ca/rootCA.pem</ssl_agent_ca>  when AGENT_CERT_VERIFICATION=true -->
  <ssl_verify_host>no</ssl_verify_host>
  <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
  <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
  <ssl_auto_negotiate>no</ssl_auto_negotiate>
  <force>
    <enabled>yes</enabled>
    <key_mismatch>yes</key_mismatch>
    <disconnected_time enabled="yes">1h</disconnected_time>
    <after_registration_time>1h</after_registration_time>
  </force>
</auth>
```

### A.2 Manual equivalent

```bash
KEY='<a strong random value>'
docker compose exec -T wazuh.manager bash -c \
  "umask 027; cat > /var/ossec/etc/authd.pass && chown root:wazuh /var/ossec/etc/authd.pass && chmod 640 /var/ossec/etc/authd.pass" \
  <<< "$KEY"
# make sure <use_password>yes</use_password> is in the <auth> block, then:
docker compose exec wazuh.manager /var/ossec/bin/wazuh-control restart
```

> If `use_password` is `yes` and `authd.pass` is missing, `wazuh-authd`
> generates a random key and prints it once in `ossec.log`. Always install
> your own key.

### A.3 Verify on the manager

```bash
docker compose exec wazuh.manager grep -i authd /var/ossec/logs/ossec.log | tail
# expected:
# wazuh-authd: INFO: Accepting connections on port 1515. Using password specified on file: etc/authd.pass
```

### A.4 Optional: certificates as a second factor (mutual TLS)

```bash
./scripts/generate-agent-certs.sh --ca                                  # once
./scripts/generate-agent-certs.sh --manager wazuh.example.com 192.0.2.10  # names agents use to reach the manager
./scripts/generate-agent-certs.sh web01 db01 dc01                       # one per agent
sed -i 's/^AGENT_CERT_VERIFICATION=.*/AGENT_CERT_VERIFICATION=true/' .env
./scripts/setup.sh            # re-renders ossec.conf and restarts; installs CA + manager cert
```

With this in place the manager only enrolls an agent that has **both** the key
and a certificate signed by the agent CA. Agents can also check that they are
talking to the real manager (`server_ca_path`). Store
`config/agent_ssl_certs/rootCA.key` offline.

### A.5 Restrict the enrollment port

- Allow 1515/tcp only from the agent networks (see doc 1, "Ports and firewall").
- If you enroll agents in batches, you can close 1515 in the firewall between
  batches. Enrolled agents only need 1514.

---

## Part B: Agent side

Replace `WAZUH_MANAGER` with the manager's DNS name or IP address and use the
same agent version as the manager (`WAZUH_VERSION`). Don't type the key on a
shared terminal where it lands in shell history. Read it with `read -s`, or
push it with your configuration management tool.

```bash
read -rs WAZUH_REGISTRATION_PASSWORD   # paste the key, press Enter
export WAZUH_REGISTRATION_PASSWORD
```

### B.1 Linux: Debian / Ubuntu

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update

WAZUH_MANAGER="wazuh.example.com" \
WAZUH_REGISTRATION_PASSWORD="$WAZUH_REGISTRATION_PASSWORD" \
WAZUH_AGENT_GROUP="default" \
WAZUH_AGENT_NAME="$(hostname -s)" \
  apt-get install -y wazuh-agent=4.12.0-1

systemctl daemon-reload && systemctl enable --now wazuh-agent
```

### B.2 Linux: RHEL / Rocky / Alma / Amazon Linux

```bash
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat > /etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

WAZUH_MANAGER="wazuh.example.com" \
WAZUH_REGISTRATION_PASSWORD="$WAZUH_REGISTRATION_PASSWORD" \
  yum install -y wazuh-agent-4.12.0-1

systemctl daemon-reload && systemctl enable --now wazuh-agent
```

### B.3 Windows (PowerShell as Administrator)

```powershell
$key = Read-Host -AsSecureString "Enrollment key"
$plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
           [Runtime.InteropServices.Marshal]::SecureStringToBSTR($key))

Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi `
  -OutFile $env:TEMP\wazuh-agent.msi
msiexec.exe /i $env:TEMP\wazuh-agent.msi /q `
  WAZUH_MANAGER="wazuh.example.com" `
  WAZUH_REGISTRATION_PASSWORD="$plain" `
  WAZUH_AGENT_GROUP="windows"
NET START WazuhSvc
Remove-Variable plain
```

For MISP hash lookups on Windows, install Sysmon with a good configuration
(for example SwiftOnSecurity or olafhartong/sysmon-modular) and collect
`Microsoft-Windows-Sysmon/Operational` in the agent `ossec.conf`.

### B.4 macOS

```bash
echo "WAZUH_MANAGER='wazuh.example.com' && WAZUH_REGISTRATION_PASSWORD='<key>'" > /tmp/wazuh_envs
curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.12.0-1.intel64.pkg  # or .arm64.pkg
sudo installer -pkg ./wazuh-agent.pkg -target /
rm -f /tmp/wazuh_envs
sudo /Library/Ossec/bin/wazuh-control start
```

### B.5 Existing agent / manual enrollment with `agent-auth`

```bash
# key only
sudo /var/ossec/bin/agent-auth -m wazuh.example.com -P "$WAZUH_REGISTRATION_PASSWORD" -A "$(hostname -s)" -G default

# key + client certificate + verify the manager (mutual TLS, part A.4)
sudo /var/ossec/bin/agent-auth -m wazuh.example.com -P "$WAZUH_REGISTRATION_PASSWORD" \
  -v /var/ossec/etc/rootCA.pem \
  -x /var/ossec/etc/sslagent.cert -k /var/ossec/etc/sslagent.key
sudo systemctl restart wazuh-agent
```

### B.6 Persistent agent configuration (auto-enrollment)

When an agent loses its key, it re-enrolls by itself using the `<enrollment>`
block in `/var/ossec/etc/ossec.conf` (Windows:
`C:\Program Files (x86)\ossec-agent\ossec.conf`):

```xml
<client>
  <server>
    <address>wazuh.example.com</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
  <enrollment>
    <enabled>yes</enabled>
    <manager_address>wazuh.example.com</manager_address>
    <port>1515</port>
    <agent_name>web01</agent_name>
    <groups>default</groups>
    <authorization_pass_path>etc/authd.pass</authorization_pass_path>
    <!-- mutual TLS (optional, part A.4) -->
    <server_ca_path>etc/rootCA.pem</server_ca_path>
    <agent_certificate_path>etc/sslagent.cert</agent_certificate_path>
    <agent_key_path>etc/sslagent.key</agent_key_path>
  </enrollment>
</client>
```

```bash
echo '<enrollment key>' | sudo tee /var/ossec/etc/authd.pass >/dev/null
sudo chown root:wazuh /var/ossec/etc/authd.pass && sudo chmod 640 /var/ossec/etc/authd.pass
# copy config/agent_ssl_certs/agents/<name>/{rootCA.pem,sslagent.cert,sslagent.key} the same way (key: 640)
sudo systemctl restart wazuh-agent
```

Trade-off: keeping `authd.pass` on the endpoint allows automatic re-enrollment,
but the key can be stolen from any compromised host. On high-value hosts,
delete `authd.pass` after the first successful enrollment.

---

## Part C: Verification

```bash
# Manager: the agent is listed and Active
docker compose exec wazuh.manager /var/ossec/bin/agent_control -l

# Agent: enrollment log
sudo grep -iE 'enroll|authd|Valid key' /var/ossec/logs/ossec.log | tail

# Negative test: enrollment without the key must FAIL
sudo /var/ossec/bin/agent-auth -m wazuh.example.com -A should-fail
#   -> ERROR: Invalid password (from manager)
```

The dashboard shows the agent under **Agents management > Summary**.

## Part D: Key rotation and cleanup

```bash
# 1. set a new ENROLLMENT_PASSWORD in .env
# 2. install it (enrolled agents are not affected)
./scripts/enable-enrollment.sh
# 3. update authd.pass on agents that keep it (auto-enrollment) and in your
#    deployment tooling (Ansible/GPO/Intune variables)
```

Remove stale or rogue agents:

```bash
docker compose exec wazuh.manager /var/ossec/bin/manage_agents -l
docker compose exec wazuh.manager /var/ossec/bin/manage_agents -r <agent_id>
```

Or through the API: `DELETE /agents?agents_list=<id>&status=all&older_than=0s`.

Rotate on a schedule, and immediately when an admin leaves or a host that
stored the key is compromised.
