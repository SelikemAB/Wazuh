# 3. Changing the default passwords (indexer admin and API)

A stock `wazuh-docker` deployment ships with these well-known credentials:

| Component | User | Stock default | Used by | `.env` variable |
|---|---|---|---|---|
| Indexer | `admin` | `SecretPassword` | Dashboard login, Filebeat (manager → indexer) | `INDEXER_ADMIN_PASSWORD` |
| Indexer | `kibanaserver` | `kibanaserver` | Dashboard backend | `DASHBOARD_KIBANASERVER_PASSWORD` |
| Wazuh API | `wazuh` | `wazuh` | API administrator | `API_ADMIN_PASSWORD` |
| Wazuh API | `wazuh-wui` | `MyS3cr37P450r.*-` | Dashboard → API | `API_WUI_PASSWORD` |
| Indexer | `kibanaro`, `logstash`, `readall`, `snapshotrestore` | same as username | not used | **removed** from `internal_users.yml` |
| TheHive | `admin@thehive.local` | `secret` | UI | change at first login (doc 4) |
| Cortex / MISP | superadmin / admin | set at first start | UI | doc 4 |

In this boilerplate **none of these defaults are used**:

- `scripts/init-env.sh` generates a unique random value for each variable.
- `scripts/wazuhctl.py validate` refuses to deploy if a password is empty,
  reused, too weak, or a known default.
- The indexer hashes are rendered **before the first boot**, so the security
  index is initialized with your passwords. `SecretPassword` never exists.
- The API passwords are replaced right after the API comes up
  (`setup.sh` → `wazuhctl.py api-set-passwords`), and the script checks that
  the defaults no longer work.

Password policy: 12-64 characters with upper case, lower case, a digit and one
of `. * + ? -`. Allowed characters are `A-Z a-z 0-9 . * + ? - _ @ = ^ ~ % , :`.
Don't use `$`, quotes, backslash, backtick, `#`, `&` or spaces, because they
break Compose interpolation or YAML.

---

## Changing or rotating passwords on a running stack

1. Edit the value in `.env` (or generate one:
   `python3 -c "import sys;sys.path.insert(0,'scripts');import wazuhctl;print(wazuhctl.gen_password())"`).
2. Run the script:

```bash
./scripts/change-passwords.sh indexer   # admin + kibanaserver
./scripts/change-passwords.sh api       # wazuh + wazuh-wui
./scripts/change-passwords.sh all       # both
```

If the `wazuh` API password was changed outside the script, pass the
current one:

```bash
read -rs CURRENT_API_ADMIN_PASSWORD; export CURRENT_API_ADMIN_PASSWORD
./scripts/change-passwords.sh api
```

---

## What the script does, and the manual equivalent

### Indexer `admin` / `kibanaserver`

1. **Hash the new password** with the indexer's bundled tool:

   ```bash
   docker run --rm -ti --entrypoint bash wazuh/wazuh-indexer:4.12.0 -c \
     'JAVA_HOME=/usr/share/wazuh-indexer/jdk bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh'
   ```

2. **Put the hash** into `config/wazuh_indexer/internal_users.yml` (the script
   renders it from `internal_users.yml.tpl`):

   ```yaml
   admin:
     hash: "$2y$12$...."
     reserved: true
     backend_roles: ["admin"]
   ```

3. **Load it into the security index** (needed on a running cluster; the file
   is only read automatically on the first boot):

   ```bash
   docker compose exec wazuh.indexer bash -c '
     export JAVA_HOME=/usr/share/wazuh-indexer/jdk
     D=/usr/share/wazuh-indexer
     bash $D/plugins/opensearch-security/tools/securityadmin.sh \
       -f $D/opensearch-security/internal_users.yml -t internalusers \
       -icl -nhnv -h localhost -p 9200 \
       -cacert $D/certs/root-ca.pem -cert $D/certs/admin.pem -key $D/certs/admin-key.pem'
   ```

4. **Update the consumers.** `INDEXER_PASSWORD` (manager/Filebeat and
   dashboard) and `DASHBOARD_PASSWORD` are read from `.env`, so recreate the
   containers:

   ```bash
   docker compose up -d --force-recreate wazuh.manager wazuh.dashboard
   ```

5. **Verify:**

   ```bash
   curl -sk -u admin:SecretPassword https://127.0.0.1:9200   # must be 401
   curl -sk -u 'admin:<new>' https://127.0.0.1:9200          # must be 200
   ```

### Wazuh API `wazuh` / `wazuh-wui`

1. **Get a token** with the current password:

   ```bash
   TOKEN=$(curl -sk -u 'wazuh:<current>' -X POST \
     "https://127.0.0.1:55000/security/user/authenticate?raw=true")
   ```

2. **Find the user IDs** (`wazuh` is normally 1, `wazuh-wui` is 2):

   ```bash
   curl -sk -H "Authorization: Bearer $TOKEN" "https://127.0.0.1:55000/security/users?pretty=true"
   ```

3. **Set the new password:**

   ```bash
   curl -sk -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"password":"<new>"}' "https://127.0.0.1:55000/security/users/1"
   ```

4. **`wazuh-wui` only:** the manager container re-applies `API_PASSWORD` at
   every start, and the dashboard reads the password from `wazuh.yml`. Both
   come from `API_WUI_PASSWORD` in `.env`, so re-render and recreate:

   ```bash
   bash -c 'source scripts/lib.sh && render_configs'
   docker compose up -d --force-recreate wazuh.manager wazuh.dashboard
   ```

5. **Verify:**

   ```bash
   curl -sk -o /dev/null -w '%{http_code}\n' -u wazuh:wazuh -X POST \
     https://127.0.0.1:55000/security/user/authenticate      # must be 401
   ```

In the dashboard, **Dashboard management > Server APIs** must show the API
entry as *Online*.

---

## After the change

- Store `.env` in your secrets vault (Vault, 1Password, ...); it is the only
  place the passwords are kept.
- Create personal dashboard accounts (**Indexer management > Security >
  Internal users**) mapped to least-privilege roles, and keep `admin` for
  break-glass use.
- Create personal API users with RBAC roles instead of sharing `wazuh`.
