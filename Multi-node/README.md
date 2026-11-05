# Wazuh multi-node: design sketch

**Status: not implemented.** This is a plan for extending the hardened
single-node boilerplate in [`../Single-node`](../Single-node) to a clustered
deployment. Nothing here has been run. Version numbers assume Wazuh 4.12.x
(the version pinned in `Single-node/.env.example`).

## Target topology

```
                      agents
                 1514 │      │ 1515 (enrollment)
                      ▼      ▼
              ┌──────────────────────┐
              │ nginx (TCP stream LB)│
              └───┬───────────────┬──┘
   1514 balanced  │               │ 1515 + 55000 → master only
            ┌─────▼────┐    ┌─────▼────┐
            │ manager  │◄──►│ manager  │   Wazuh cluster, port 1516
            │ worker   │    │ master   │   (shared key, TLS between nodes)
            └─────┬────┘    └─────┬────┘
                  │ Filebeat → all indexers (round robin)
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
**1 master + 1 or more workers**, 1 dashboard, 1 load balancer. Dashboard
and load balancer stay single points of failure unless you add more.

## What changes, component by component

### Indexer (3 nodes)
- Replace `discovery.type: single-node` with a real cluster in
  `wazuh1/2/3.indexer.yml`:
  `cluster.name`, per-node `node.name`, `network.host`,
  `discovery.seed_hosts` (the other two), `cluster.initial_master_nodes`
  (all three), `node.max_local_storage_nodes: 3`.
- `plugins.security.nodes_dn` must list every node certificate DN, and
  `plugins.security.authcz.admin_dn` the admin cert.
- Each node gets its own named volume and its own cert/key pair.
- `vm.max_map_count=262144` on every host, heap sized per host
  (`OPENSEARCH_JAVA_OPTS`). Budget roughly 4 GB RAM per indexer to start.
- Passwords: `securityadmin.sh` writes the security index once and the
  result replicates, so `change-passwords.sh indexer` still runs once, but
  against any one node with `-h` pointing at it and with all nodes healthy.

### Certificates
- Extend `config/certs.yml` for the generator: `indexer` ×3, `server`
  (managers) ×2+, `dashboard` ×1. Output names follow the node names
  (`wazuh1.indexer.pem`, `wazuh.master.pem`, ...).
- `generate-certs.sh` stays structurally the same; only the node list and
  the volume mounts in the compose file change.

### Managers (1 master + N workers)
- Enable the cluster block on every manager (currently
  `<disabled>yes</disabled>`):
  ```xml
  <cluster>
    <name>wazuh</name>
    <node_name>${NODE_NAME}</node_name>        <!-- master / worker1 / ... -->
    <node_type>${NODE_TYPE}</node_type>         <!-- master | worker -->
    <key>${WAZUH_CLUSTER_KEY}</key>             <!-- same 32 hex everywhere -->
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes><node>wazuh.master</node></nodes>    <!-- always the master -->
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>
  ```
  `wazuhctl.py render` must therefore render **one `ossec.conf` per node**
  (`NODE_NAME`/`NODE_TYPE` placeholders), because `ossec.conf` is local to
  each node and is not synced.
- Each manager has its own volumes (`etc`, `logs`, `queue`, ...), so the
  compose file needs a service block per node (or a templated block).
- Filebeat on every manager must ship to **all** indexers: a `hosts:` list
  instead of the single `INDEXER_URL` the container currently takes. This
  likely means mounting a rendered `filebeat.yml`.
- What the cluster syncs from the master: `etc/rules`, `etc/decoders`, CDB
  lists, shared agent groups/configs, agent keys, and the API RBAC
  database. What it does **not** sync: `ossec.conf`, `etc/authd.pass`,
  `/var/ossec/integrations`, active-response binaries, agent CA/manager
  certs. Those must be installed on the node(s) that need them.

### Enrollment and agents
- `wazuh-authd` (1515) and the registration flow go to the **master only**.
  The load balancer routes 1515 to the master; 1514 is balanced across all
  nodes. Agents can also be pointed at a node directly.
- `enable-enrollment.sh` installs `authd.pass`, the agent CA and the
  manager cert on the master; add the manager cert to workers if agents
  verify the manager through the balancer.
- Agent `<manager><address>` should be the load balancer name, and the
  manager certificate SAN must include it (`generate-agent-certs.sh
  --manager <lb-fqdn>` already supports extra names).

### Load balancer
- nginx `stream` (or HAProxy) with:
  `1514 → all managers (least_conn)`, `1515 → master`,
  `55000 → master`.
- Keep 55000 bound to a restricted address, as in the single-node setup.

### Dashboard
- `opensearch.hosts` becomes the list of all three indexers.
- `wazuh.yml` API entry points at the master (or the LB's 55000).
- Mount the dashboard cert plus root CA as today.

### Integrations (MISP, TheHive, Cortex, Shuffle)
- `integratord` runs on whichever node analyzes an event, so
  `install-integrations.sh` must run on **every** manager, and each
  node's `ossec.conf` needs the `<integration>` blocks.
- Custom rules/decoders only need to be installed on the **master**; they
  are synced to workers, and `analysisd -t` validation should run on the
  master before restart.
- Shuffle: the webhook URL is the same for all nodes. If each node calls it,
  workflows must dedupe by alert id, which they currently do not.

## Impact on the existing scripts

| Script / file | Change needed |
|---|---|
| `docker-compose.yml` | 3 indexer, ≥2 manager, 1 dashboard, 1 nginx services; per-node volumes |
| `config/certs.yml` | all node names |
| `config/wazuh_indexer/*.yml` | one file per indexer node |
| `config/wazuh_cluster/*.tpl` | node-aware template; cluster enabled |
| `lib.sh` | `mgr` takes a node name (it hardcodes `wazuh.manager`); `wait_for_indexer` checks cluster health (`green`/`yellow`, 3 nodes) |
| `wazuhctl.py render` | render per-node `ossec.conf`; Filebeat config; dashboard hosts |
| `wazuhctl.py api-*` | talk to the master; RBAC changes replicate |
| `setup.sh` | ordering: indexers → master → workers → dashboard |
| `enable-enrollment.sh` | master-only, plus cert distribution |
| `install-integrations.sh` | loop over all managers; rules/decoders on master |
| `change-passwords.sh` | indexer step once per cluster; manager/dashboard recreate for all nodes |

## Suggested build order

1. Cluster only the indexers (3 nodes), keep one manager, confirm
   `GET _cluster/health` is green and shards allocate across nodes.
2. Add Filebeat multi-host output and the dashboard host list.
3. Enable the Wazuh cluster: master + one worker, check
   `cluster_control -l` and that agent groups and rules sync.
4. Add the load balancer and move agents to it; verify enrollment goes to
   the master only.
5. Port the integration and Shuffle steps, with alert dedupe.
6. Failure tests: stop one indexer, stop the worker, stop the master (agents
   keep sending to workers; enrollment and API are unavailable until the
   master is back).

## Open questions

- **Migration from single-node.** Not in place: a one-node indexer cannot
  simply join a new 3-node cluster. Plan on snapshot/restore or reindex into
  the new cluster, and re-enrolling or copying `client.keys` for agents.
- **Master failover.** Wazuh has no automatic master election; losing the
  master means manual promotion of a worker.
- **Hosts.** A real multi-node deployment belongs on multiple hosts
  (Docker Swarm/Kubernetes or one compose per host), not one machine. This
  sketch is for a compose-on-one-host lab; production needs the nodes spread
  across hosts and a different network layer.
