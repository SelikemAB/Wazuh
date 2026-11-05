# Wazuh multi-node: design sketch

**Status: not implemented.** This is a plan for extending the hardened
single-node boilerplate in [`../Single-node`](../Single-node) to a clustered
deployment. Nothing here has been run.

It was checked against the official `wazuh/wazuh-docker` v4.12.0
`multi-node/` files (compose, nginx, indexer, manager and worker configs) and
against Wazuh's documentation as summarized by search. Items that could not
be confirmed are marked **(unverified)**.

## Decide the Wazuh version first

- `Single-node/.env.example` pins **4.12.0**. Wazuh now publishes 4.14.x
  patch releases, including security fixes in agent enrollment (`authd`) and
  cluster file handling. Move to the latest 4.14.x before building anything.
- **Wazuh 5.0** was at release-candidate stage at the time of writing
  **(unverified: based on vendor announcements, not final release notes)**.
  It reportedly removes Filebeat from the pipeline and moves enrollment to
  HTTPS on port 1517 (1515 kept only for legacy agents). If you target 5.0,
  the Filebeat and port-1515 sections below change. Check
  <https://documentation.wazuh.com/current/release-notes/> first.

The rest of this document assumes **4.x**.

## Target topology

```
                      agents
                 1514 │      │ 1515 (enrollment)
                      ▼      ▼
              ┌──────────────────────┐
              │ nginx (TCP stream LB)│
              └───┬───────────────┬──┘
  1514, hash by   │               │ 1515 + 55000 → master
  client IP       │               │
            ┌─────▼────┐    ┌─────▼────┐
            │ manager  │◄──►│ manager  │   Wazuh cluster, port 1516
            │ worker   │    │ master   │   (shared key)
            └─────┬────┘    └─────┬────┘
                  │ Filebeat + <indexer> block → all indexers
        ┌─────────┼─────────────┐
   ┌────▼───┐ ┌───▼────┐ ┌──────▼─┐
   │indexer1│ │indexer2│ │indexer3│   OpenSearch cluster, ports 9200/9300
   └────┬───┘ └───┬────┘ └───┬────┘
        └─────────┼──────────┘
              ┌───▼─────┐
              │dashboard│ → all three indexers, API on the master
              └─────────┘
```

Minimum useful size: **3 indexer nodes** (quorum, survives one failure),
**1 master + 1 or more workers**, 1 dashboard, 1 load balancer. The
dashboard, the load balancer and the master stay single points of failure.

## What changes, component by component

### Indexer (3 nodes)
- Replace `discovery.type: single-node` with a real cluster in
  `wazuh1/2/3.indexer.yml`, as the official files do: `cluster.name`,
  per-node `node.name` and `network.host`, `discovery.seed_hosts` and
  `cluster.initial_master_nodes` (all three), `node.max_local_storage_nodes: 3`.
- `plugins.security.nodes_dn` must list the DN of **every indexer and the
  Filebeat certificate** (`CN=filebeat,...`), and `authcz.admin_dn` the admin
  cert.
- Each node gets its own named volume and its own cert/key pair.
- `vm.max_map_count=262144` on every host. The official setup uses a 1 GB
  heap per indexer (`OPENSEARCH_JAVA_OPTS`); size it for your data volume.
- Passwords: `securityadmin.sh` writes the security index once and it
  replicates, so `change-passwords.sh indexer` still runs once, against one
  node, with all nodes healthy.

### Certificates
- Extend `config/certs.yml` for the generator: `indexer` ×3, `server`
  (managers) ×2+, `dashboard` ×1. Output file names follow the node names
  (`wazuh1.indexer.pem`, `wazuh.master.pem`, ...).
- `generate-certs.sh` keeps its structure; only the node list and the volume
  mounts change.

### Managers (1 master + N workers)
- Enable the cluster block on every manager (the single-node template has
  `<disabled>yes</disabled>`):
  ```xml
  <cluster>
    <name>wazuh</name>
    <node_name>${NODE_NAME}</node_name>        <!-- master / worker01 / ... -->
    <node_type>${NODE_TYPE}</node_type>         <!-- master | worker -->
    <key>${WAZUH_CLUSTER_KEY}</key>             <!-- same 32 hex everywhere -->
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes><node>wazuh.master</node></nodes>    <!-- always the master -->
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>
  ```
  `ossec.conf` is local to each node and is **not** synced, so
  `wazuhctl.py render` must produce one file per node (`NODE_NAME` and
  `NODE_TYPE` placeholders).
- **The `<indexer>` block** in `ossec.conf` (used by vulnerability
  detection) must list all three indexers. The single-node template
  (`wazuh_manager.conf.tpl`) lists one host; the official multi-node configs
  list `wazuh1/2/3.indexer:9200`.
- **Filebeat** on every manager must also ship to all indexers. The wazuh-docker
  containers take a single `INDEXER_URL`, and I found no confirmation that a
  comma-separated list works **(unverified)**. Plan to mount a rendered
  `filebeat.yml` with a `hosts:` list instead. Outside Docker, Wazuh documents
  a comma-separated host list with failover.
- Each manager has its own volumes (`etc`, `logs`, `queue`, ...), so the
  compose file needs a service block per node.
- **Synced from the master to workers:** agent keys, shared agent
  configuration and groups, CDB lists, custom rules, custom decoders, custom
  SCA policies. Local edits to these on a worker are overwritten.
- **Not synced:** `ossec.conf`, `etc/authd.pass` **(unverified for 4.12)**,
  `/var/ossec/integrations`, active-response binaries, agent CA and manager
  certs. Whether the cluster also syncs API users and roles is
  **unverified**; check before relying on it.
- Older docs say workers do not restart when rules or decoders sync and must
  be restarted to apply them **(unverified for current versions)**. If that
  holds, `install-integrations.sh` must restart every node, not only the
  master.

### Enrollment and agents
- `wazuh-authd` (1515) runs on workers too, and they forward registration
  requests to the master. The official Docker setup still publishes 1515
  and 55000 on the master only; copy that.
- The enrollment password lives on the master. How it reaches workers varies
  by version, so test enrolling an agent against a worker **(unverified)**.
- `<use_source_ip>` must be `no` on the master when agents register through a
  load balancer. The single-node template already sets it to `no`.
- Agents point at the load balancer name; the manager certificate SAN must
  include it (`generate-agent-certs.sh --manager <lb-fqdn>` supports extra
  names).

### Load balancer
- nginx `stream` or HAProxy. Wazuh's own guidance and the official nginx
  config hash on the client IP so an agent keeps talking to the same node:
  ```
  upstream mycluster { hash $remote_addr consistent; server wazuh.master:1514; server wazuh.worker:1514; }
  ```
  Wazuh's current docs list only the workers in the reporting upstream and
  put the master in a separate registration upstream; the official Docker
  file lists both **(versions differ, pick one deliberately)**.
- 1515 and 55000: master only.
- Keep 55000 bound to a restricted address, as in the single-node setup.

### Dashboard
- `OPENSEARCH_HOSTS` becomes the list of all three indexers (the official
  Docker setup lists only `wazuh1.indexer`, which is itself a single point of
  failure).
- `wazuh.yml` API entry points at the master.
- Mount the dashboard cert plus root CA as today.

### Integrations (MISP, TheHive, Cortex, Shuffle)
- `integratord` runs on whichever node analyzes an event, so
  `install-integrations.sh` must run on **every** manager and each node's
  `ossec.conf` needs the `<integration>` blocks.
- Custom rules and decoders only need installing on the **master**; they sync
  to workers. Run `analysisd -t` on the master before restarting.
- Shuffle: the webhook URL is the same for all nodes, and each node sends the
  alerts it analyzed, so there are no duplicates by design. Verify this when
  testing; if duplicates appear, dedupe by alert id in the workflows.

## Impact on the existing scripts

| Script / file | Change needed |
|---|---|
| `docker-compose.yml` | 3 indexer, ≥2 manager, 1 dashboard, 1 nginx services; per-node volumes |
| `config/certs.yml` | all node names, including `filebeat` |
| `config/wazuh_indexer/*.yml` | one file per indexer node |
| `config/wazuh_cluster/*.tpl` | node-aware template; cluster enabled; `<indexer>` lists all hosts |
| `lib.sh` | `mgr` takes a node name (it hardcodes `wazuh.manager`); `wait_for_indexer` checks cluster health and node count |
| `wazuhctl.py render` | per-node `ossec.conf`; Filebeat config; dashboard hosts |
| `wazuhctl.py api-*` | talk to the master |
| `setup.sh` | ordering: indexers → master → workers → dashboard |
| `enable-enrollment.sh` | master first, then verify a worker-routed enrollment |
| `install-integrations.sh` | loop over all managers; rules and decoders on the master; restart every node |
| `change-passwords.sh` | indexer step once per cluster; recreate every manager and the dashboard |

## Suggested build order

1. Cluster only the indexers (3 nodes), keep one manager, confirm
   `GET _cluster/health` is green and shards spread across nodes.
2. Switch Filebeat and the `<indexer>` block to all three hosts, and the
   dashboard host list.
3. Enable the Wazuh cluster: master + one worker. Check `cluster_control -l`
   and that agent groups and rules sync.
4. Add the load balancer and move agents to it; test enrollment through the
   balancer and directly against a worker.
5. Port the integration and Shuffle steps.
6. Failure tests: stop one indexer, stop the worker, stop the master. Agents
   should keep reporting to workers; enrollment, the API and the dashboard's
   Wazuh app are unavailable until the master is back.

## Open questions

- **Migration from single-node.** Not in place: a one-node indexer cannot
  simply join a new 3-node cluster. Plan on snapshot/restore or reindex into
  the new cluster, and copying `client.keys` or re-enrolling agents.
- **Master failover.** Wazuh has no automatic master election. Promoting a
  worker by hand is possible but, per Wazuh staff on the mailing list, not
  officially documented.
- **Hosts.** A real multi-node deployment belongs on several hosts (Swarm,
  Kubernetes, or one compose project per host). This sketch fits a
  compose-on-one-host lab; production needs the nodes spread across hosts.

## Sources

- [wazuh-docker v4.12.0 multi-node files](https://github.com/wazuh/wazuh-docker/tree/v4.12.0/multi-node)
- [Wazuh docs: Load balancers](https://documentation.wazuh.com/current/user-manual/wazuh-server-cluster/load-balancers.html)
- [Wazuh blog: nginx load balancer in a Wazuh cluster](https://wazuh.com/blog/nginx-load-balancer-in-a-wazuh-cluster/)
- [Wazuh docs: Types of nodes](https://documentation.wazuh.com/current/user-manual/wazuh-server-cluster/types-of-nodes.html)
- [Wazuh cluster development docs (4.7)](https://documentation.wazuh.com/4.7/development/wazuh-cluster.html)
- [Wazuh docs: installing the server step by step](https://documentation.wazuh.com/current/installation-guide/wazuh-server/step-by-step.html)
- [Wazuh release notes](https://documentation.wazuh.com/current/release-notes/)
- [wazuh/wazuh issue #21297](https://github.com/wazuh/wazuh/issues/21297)
- [Mailing list: master node down](https://groups.google.com/g/wazuh/c/MCnpIg1Sk7I)
