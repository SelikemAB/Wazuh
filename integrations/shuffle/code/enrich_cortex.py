# Step "enrich_cortex": run the configured Cortex analyzers on the IoC
# observables, wait for the reports and post a summary as a case comment.
EXTRACT = load(r"""$enrich_extract.message""")
HIVE = load(r"""$enrich_thehive.message""")
CORTEX_URL = cfg("$cortex_url").rstrip("/")
CORTEX_KEY = cfg("$cortex_api_key")
ANALYZERS = csv(cfg("$cortex_analyzers", "MISP_2_1"))
HIVE_URL = cfg("$thehive_url").rstrip("/")
HIVE_KEY = cfg("$thehive_api_key")
ORG = cfg("$thehive_organisation")
VERIFY = as_bool(cfg("$verify_ssl", "false"))
MAX_JOBS = 10

C_HEADERS = {"Authorization": "Bearer " + CORTEX_KEY, "Content-Type": "application/json"}
H_HEADERS = {"Authorization": "Bearer " + HIVE_KEY, "Content-Type": "application/json"}
if ORG:
    H_HEADERS["X-Organisation"] = ORG

out = {"jobs": [], "commented": False}
if not (CORTEX_URL and CORTEX_KEY):
    out["error"] = "cortex_url / cortex_api_key workflow variables not set"
    emit(out)
    raise SystemExit(0)

by_type = {}
jobs = []
for o in [o for o in EXTRACT.get("observables", []) if o.get("ioc")]:
    dt = o["dataType"]
    if dt not in by_type:
        r = requests.get(CORTEX_URL + "/api/analyzer/type/" + dt, headers=C_HEADERS, verify=VERIFY, timeout=20)
        by_type[dt] = [a for a in (r.json() if r.ok else []) if a.get("name") in ANALYZERS]
    for analyzer in by_type[dt]:
        if len(jobs) >= MAX_JOBS:
            break
        r = requests.post(CORTEX_URL + "/api/analyzer/%s/run" % analyzer["id"], headers=C_HEADERS,
                          json={"data": o["data"], "dataType": dt, "tlp": 2,
                                "message": "Shuffle - Wazuh alert %s" % EXTRACT.get("alert_id")},
                          verify=VERIFY, timeout=20)
        if r.ok:
            jobs.append((analyzer["name"], o["data"], r.json().get("id")))

lines = []
for name, data, job_id in jobs:
    entry = {"analyzer": name, "data": data, "job_id": job_id, "status": "Unknown", "taxonomies": []}
    try:
        r = requests.get(CORTEX_URL + "/api/job/%s/waitreport?atMost=1minute" % job_id,
                         headers=C_HEADERS, verify=VERIFY, timeout=90)
        job = r.json()
        entry["status"] = job.get("status")
        taxonomies = ((job.get("report") or {}).get("summary") or {}).get("taxonomies", [])
        entry["taxonomies"] = ["%s:%s=%s (%s)" % (t.get("namespace"), t.get("predicate"), t.get("value"), t.get("level"))
                               for t in taxonomies]
    except Exception as exc:
        entry["error"] = str(exc)[:200]
    out["jobs"].append(entry)
    lines.append("| %s | `%s` | %s | %s |" % (name, data, entry["status"], "<br>".join(entry["taxonomies"]) or "-"))

if HIVE.get("case_id") and lines and HIVE_URL and HIVE_KEY:
    message = "### Cortex analysis (Shuffle)\n\n| Analyzer | Observable | Status | Result |\n|---|---|---|---|\n" + "\n".join(lines)
    r = requests.post(HIVE_URL + "/api/v1/case/%s/comment" % HIVE["case_id"], headers=H_HEADERS,
                      json={"message": message}, verify=VERIFY, timeout=20)
    out["commented"] = r.ok
emit(out)
