"""
Data ingestion pipeline for VulnGraph.

1. Parses package manifests (requirements.txt and package-lock.json) from data/manifests/
2. Resolves vulnerabilities via OSV.dev API (with local disk caching in data/osv_cache/)
3. Seeds deterministic enterprise architecture topology (~15 services, calls, datastores, teams)
4. Plants ground-truth evaluation scenarios:
   - 3 "Sleeper" vulnerabilities: Medium CVSS (~5.0 - 6.5) but on critical internet -> sensitive data path
   - 3 "Decoy" vulnerabilities: Critical CVSS (9.6 - 9.8) but isolated/internal with low data impact
5. Populates FalkorDB graph using parameterized Cypher queries and logs node/edge verification counts.
"""

import os
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
import requests
from dotenv import load_dotenv

load_dotenv()

from schema import get_graph, init_schema, clear_graph

BASE_DIR = Path(__file__).resolve().parent
MANIFESTS_DIR = BASE_DIR / "data" / "manifests"
CACHE_DIR = BASE_DIR / "data" / "osv_cache"

CACHE_DIR.mkdir(parents=True, exist_ok=True)
MANIFESTS_DIR.mkdir(parents=True, exist_ok=True)

# Ground-truth planted scenarios for evaluation:
# 3 Sleepers: Medium CVSS, Internet-facing ingress, High-sensitivity DataStore path
# 3 Decoys: Critical CVSS, Isolated/Internal, No path to sensitive data
PLANTED_SCENARIOS = [
    {
        "id": "CVE-2023-SLEEPER-01",
        "cvss": 5.3,
        "summary": "Authority parser backtracking vulnerability leading to connection bypass in urllib3",
        "fix_version": "1.26.5",
        "package_name": "urllib3",
        "package_version": "1.26.4",
        "scenario_type": "sleeper"
    },
    {
        "id": "CVE-2023-SLEEPER-02",
        "cvss": 5.9,
        "summary": "Insecure key verification flaw allowing signature bypass in jsonwebtoken",
        "fix_version": "9.0.0",
        "package_name": "jsonwebtoken",
        "package_version": "8.5.1",
        "scenario_type": "sleeper"
    },
    {
        "id": "CVE-2023-SLEEPER-03",
        "cvss": 6.1,
        "summary": "Prototype pollution vulnerability via defaultsDeep and zipObjectDeep in lodash",
        "fix_version": "4.17.21",
        "package_name": "lodash",
        "package_version": "4.17.19",
        "scenario_type": "sleeper"
    },
    {
        "id": "CVE-2021-DECOY-01",
        "cvss": 9.8,
        "summary": "Critical authentication bypass in Paramiko server transport thread prior to handshake completion",
        "fix_version": "2.7.3",
        "package_name": "paramiko",
        "package_version": "2.7.2",
        "scenario_type": "decoy"
    },
    {
        "id": "CVE-2022-DECOY-02",
        "cvss": 9.8,
        "summary": "Critical buffer overflow and remote heap memory corruption in Pillow image parser",
        "fix_version": "8.1.2",
        "package_name": "pillow",
        "package_version": "8.1.0",
        "scenario_type": "decoy"
    },
    {
        "id": "CVE-2023-DECOY-03",
        "cvss": 9.6,
        "summary": "Critical timing oracle flaw in RSA PKCS#1 v1.5 decryption allowing remote ciphertext recovery",
        "fix_version": "4.7",
        "package_name": "rsa",
        "package_version": "4.6",
        "scenario_type": "decoy"
    }
]


def parse_requirements_txt(file_path: Path) -> List[Dict[str, str]]:
    """
    Parses a requirements.txt file into a list of {name, version, ecosystem} dicts.
    """
    packages = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*[=><~]=?\s*([a-zA-Z0-9_\-\.]+)", line)
            if match:
                pkg_name = match.group(1).lower()
                pkg_version = match.group(2)
                packages.append({
                    "name": pkg_name,
                    "version": pkg_version,
                    "ecosystem": "PyPI"
                })
    return packages


def parse_package_lock_json(file_path: Path) -> List[Dict[str, str]]:
    """
    Parses a package-lock.json file into a list of {name, version, ecosystem} dicts.
    """
    packages = []
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "packages" in data:
        for pkg_path, pkg_info in data["packages"].items():
            if not pkg_path:
                continue
            name = pkg_path.split("node_modules/")[-1]
            version = pkg_info.get("version")
            if name and version:
                packages.append({
                    "name": name.lower(),
                    "version": version,
                    "ecosystem": "npm"
                })
    elif "dependencies" in data:
        for name, info in data["dependencies"].items():
            version = info.get("version")
            if version:
                packages.append({
                    "name": name.lower(),
                    "version": version,
                    "ecosystem": "npm"
                })
    return packages


def query_osv_vulnerabilities(name: str, version: str, ecosystem: str) -> List[Dict[str, Any]]:
    """
    Queries OSV.dev for vulnerabilities affecting package@version.
    Uses on-disk cache data/osv_cache/ for offline reproducibility.
    """
    clean_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", name)
    clean_ver = re.sub(r"[^a-zA-Z0-9_\-]", "_", version)
    cache_file = CACHE_DIR / f"{clean_name}_{clean_ver}.json"

    if cache_file.exists():
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return extract_vulns_from_osv(data, name)
        except Exception as e:
            print(f"[OSV Cache] Read error for {cache_file.name}: {e}")

    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": name,
            "ecosystem": ecosystem
        },
        "version": version
    }

    try:
        resp = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return extract_vulns_from_osv(data, name)
        else:
            print(f"[OSV API] HTTP status {resp.status_code} for {name}@{version}")
    except Exception as e:
        print(f"[OSV API] Query failed for {name}@{version}: {e}. Falling back to empty.")

    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump({"vulns": []}, f, indent=2)

    return []


def check_osv_fetch(pkg_name: str = "requests", version: str = "2.25.1", ecosystem: str = "PyPI") -> Dict[str, Any]:
    """
    Directly tests fetching live vulnerability findings from open-source OSV.dev API
    (public open-source service, no API key required).
    """
    print("=" * 60)
    print("CHECKING LIVE OSV.DEV OPEN-SOURCE DATA FETCH")
    print("=" * 60)
    print(f"Target Package : {pkg_name}@{version} ({ecosystem})")
    print("API Endpoint   : https://api.osv.dev/v1/query (Public Open Source)")

    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": pkg_name,
            "ecosystem": ecosystem
        },
        "version": version
    }
    headers = {"Content-Type": "application/json"}

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=8)
        print(f"HTTP Status    : {resp.status_code} {resp.reason}")
        if resp.status_code == 200:
            data = resp.json()
            vulns = extract_vulns_from_osv(data, pkg_name)
            print(f"Findings Found : {len(vulns)}")
            for idx, v in enumerate(vulns[:5], 1):
                print(f"  [{idx}] {v['id']} (CVSS: {v['cvss']}) - {v['summary'][:60]}... (Fix: {v['fix_version']})")
            if len(vulns) > 5:
                print(f"  ... and {len(vulns) - 5} more findings")
            print("=" * 60)
            return {"status": "success", "count": len(vulns), "vulns": vulns}
        else:
            print(f"Response Body  : {resp.text[:200]}")
            print("=" * 60)
            return {"status": "error", "code": resp.status_code, "error": resp.text}
    except Exception as e:
        print(f"Connection Err : {e}")
        print("=" * 60)
        return {"status": "exception", "error": str(e)}


def extract_vulns_from_osv(osv_data: Dict[str, Any], pkg_name: str) -> List[Dict[str, Any]]:
    """
    Normalizes OSV response objects into clean finding dictionaries.
    """
    extracted = []
    vulns = osv_data.get("vulns", [])
    for v in vulns:
        vid = v.get("id")
        summary = v.get("summary") or v.get("details", "")[:120] or f"Vulnerability in {pkg_name}"

        cvss = 5.0
        db_specific = v.get("database_specific", {})
        if "cvss_score" in db_specific:
            cvss = float(db_specific["cvss_score"])
        elif "severity" in v and isinstance(v["severity"], list):
            for s in v["severity"]:
                if s.get("type") in ("CVSS_V3", "CVSS_V4"):
                    score_str = s.get("score", "")
                    match = re.search(r"/([0-9]\.[0-9])", score_str)
                    if match:
                        cvss = float(match.group(1))
                    elif "baseScore" in s:
                        cvss = float(s["baseScore"])
        elif "severity" in db_specific:
            sev = str(db_specific["severity"]).upper()
            if "CRIT" in sev:
                cvss = 9.8
            elif "HIGH" in sev:
                cvss = 7.5
            elif "MOD" in sev or "MED" in sev:
                cvss = 5.5
            elif "LOW" in sev:
                cvss = 3.0

        fix_ver = "unknown"
        for aff in v.get("affected", []):
            for r in aff.get("ranges", []):
                for ev in r.get("events", []):
                    if "fixed" in ev:
                        fix_ver = ev["fixed"]
                        break

        extracted.append({
            "id": vid,
            "cvss": float(cvss),
            "summary": summary,
            "fix_version": fix_ver
        })
    return extracted


def build_enterprise_topology():
    """
    Returns synthetic, deterministic enterprise microservice architecture:
    ~15 services, teams, datastores, and call graph edges.
    """
    teams = [
        {"name": "sec-core"},
        {"name": "checkout-squad"},
        {"name": "identity-team"},
        {"name": "platform-infra"},
        {"name": "analytics-team"}
    ]

    datastores = [
        {"name": "customer-pII-db", "sensitivity": "high"},
        {"name": "payment-vault", "sensitivity": "high"},
        {"name": "user-credentials-store", "sensitivity": "high"},
        {"name": "order-history-db", "sensitivity": "medium"},
        {"name": "product-catalog-db", "sensitivity": "low"},
        {"name": "audit-archive", "sensitivity": "low"}
    ]

    services = [
        # Ingress / Gateway Services (Internet Facing)
        {"name": "api-gateway", "internet_facing": True, "team": "sec-core"},
        {"name": "auth-service", "internet_facing": True, "team": "identity-team"},
        {"name": "checkout-service", "internet_facing": True, "team": "checkout-squad"},
        {"name": "search-service", "internet_facing": True, "team": "platform-infra"},

        # Internal Core Services (Non Internet Facing)
        {"name": "payment-service", "internet_facing": False, "team": "checkout-squad"},
        {"name": "user-profile-service", "internet_facing": False, "team": "identity-team"},
        {"name": "order-service", "internet_facing": False, "team": "checkout-squad"},
        {"name": "inventory-service", "internet_facing": False, "team": "platform-infra"},
        {"name": "notification-service", "internet_facing": False, "team": "platform-infra"},
        {"name": "billing-worker", "internet_facing": False, "team": "checkout-squad"},

        # Backend Analytics, Audit & Internal Tools (Non Internet Facing)
        {"name": "reporting-service", "internet_facing": False, "team": "analytics-team"},
        {"name": "analytics-pipeline", "internet_facing": False, "team": "analytics-team"},
        {"name": "audit-logger", "internet_facing": False, "team": "sec-core"},
        {"name": "internal-dev-tool", "internet_facing": False, "team": "platform-infra"},
        {"name": "legacy-backup-service", "internet_facing": False, "team": "platform-infra"},
    ]

    # Service -> READS -> DataStore
    reads_edges = [
        ("user-profile-service", "customer-pII-db"),
        ("payment-service", "payment-vault"),
        ("auth-service", "user-credentials-store"),
        ("order-service", "order-history-db"),
        ("inventory-service", "product-catalog-db"),
        ("search-service", "product-catalog-db"),
        ("audit-logger", "audit-archive"),
        ("analytics-pipeline", "product-catalog-db"),
        ("internal-dev-tool", "audit-archive"),
        ("legacy-backup-service", "audit-archive"),
    ]

    # Service -> CALLS -> Service
    call_edges = [
        ("api-gateway", "auth-service"),
        ("api-gateway", "user-profile-service"),
        ("api-gateway", "search-service"),
        ("checkout-service", "payment-service"),
        ("checkout-service", "order-service"),
        ("checkout-service", "inventory-service"),
        ("payment-service", "billing-worker"),
        ("order-service", "notification-service"),
        ("reporting-service", "analytics-pipeline"),
        ("reporting-service", "audit-logger"),
    ]

    # Package -> DEPENDS_ON -> Package (transitive dependencies)
    package_dependencies = [
        (("express", "4.17.1"), ("lodash", "4.17.19")),
        (("requests", "2.25.1"), ("urllib3", "1.26.4")),
        (("requests", "2.25.1"), ("certifi", "2020.12.5")),
        (("boto3", "1.17.1"), ("rsa", "4.6")),
        (("pandas", "1.1.5"), ("numpy", "1.19.4")),
    ]

    return teams, datastores, services, reads_edges, call_edges, package_dependencies


def ingest_all():
    """
    Main ingestion execution function.
    """
    print("=" * 60)
    print("Starting VulnGraph FalkorDB Ingestion Pipeline")
    print("=" * 60)

    graph = get_graph()

    # Step 1: Clean reset and schema indexing
    print("[1/5] Resetting graph and creating schema indexes...")
    clear_graph(graph)
    init_schema(graph)

    # Step 2: Load and parse package manifests
    print("[2/5] Parsing package manifests and querying OSV vulnerabilities...")
    manifest_files = list(MANIFESTS_DIR.glob("*"))
    all_packages: Dict[str, Dict[str, Any]] = {}
    service_packages: Dict[str, List[Dict[str, str]]] = {}
    vulnerabilities: Dict[str, Dict[str, Any]] = {}
    package_vulns: List[Dict[str, Any]] = []

    manifest_service_map = {
        "checkout_service_requirements.txt": "checkout-service",
        "auth_service_package-lock.json": "auth-service",
        "api_gateway_package-lock.json": "api-gateway",
        "internal_dev_tool_requirements.txt": "internal-dev-tool",
        "analytics_pipeline_requirements.txt": "analytics-pipeline",
        "legacy_backup_requirements.txt": "legacy-backup-service",
        "notification_service_package-lock.json": "notification-service",
        "payment_service_requirements.txt": "payment-service",
    }

    for mf in manifest_files:
        svc_name = manifest_service_map.get(mf.name)
        if not svc_name:
            continue

        if mf.name.endswith(".json"):
            pkgs = parse_package_lock_json(mf)
        else:
            pkgs = parse_requirements_txt(mf)

        service_packages[svc_name] = pkgs
        for p in pkgs:
            key = f"{p['name']}@{p['version']}"
            all_packages[key] = p

            vulns = query_osv_vulnerabilities(p["name"], p["version"], p["ecosystem"])
            for v in vulns:
                vulnerabilities[v["id"]] = v
                package_vulns.append({
                    "vuln_id": v["id"],
                    "package_name": p["name"],
                    "package_version": p["version"]
                })

    # Explicitly inject the 6 planted ground-truth evaluation scenarios
    print("[3/5] Injecting 6 planted evaluation scenarios (3 Sleepers & 3 Decoys)...")
    for scenario in PLANTED_SCENARIOS:
        vulnerabilities[scenario["id"]] = {
            "id": scenario["id"],
            "cvss": scenario["cvss"],
            "summary": scenario["summary"],
            "fix_version": scenario["fix_version"]
        }
        package_vulns.append({
            "vuln_id": scenario["id"],
            "package_name": scenario["package_name"],
            "package_version": scenario["package_version"]
        })
        # Ensure package exists in all_packages
        pkg_key = f"{scenario['package_name']}@{scenario['package_version']}"
        if pkg_key not in all_packages:
            all_packages[pkg_key] = {
                "name": scenario["package_name"],
                "version": scenario["package_version"]
            }

    print(f"      Parsed {len(manifest_files)} manifests.")
    print(f"      Total unique packages: {len(all_packages)}")
    print(f"      Total vulnerabilities registered: {len(vulnerabilities)}")

    # Step 3: Insert Packages and Vulnerabilities
    print("[4/5] Inserting Vulnerabilities, Packages, and AFFECTS relationships...")
    for v in vulnerabilities.values():
        graph.query(
            "MERGE (v:Vuln {id: $id}) "
            "SET v.cvss = $cvss, v.summary = $summary, v.fix_version = $fix_version",
            {"id": v["id"], "cvss": float(v["cvss"]), "summary": v["summary"], "fix_version": v["fix_version"]}
        )

    for p in all_packages.values():
        graph.query(
            "MERGE (p:Package {name: $name, version: $version})",
            {"name": p["name"], "version": p["version"]}
        )

    for pv in package_vulns:
        graph.query(
            "MATCH (v:Vuln {id: $vid}), (p:Package {name: $pname, version: $pver}) "
            "MERGE (v)-[:AFFECTS]->(p)",
            {"vid": pv["vuln_id"], "pname": pv["package_name"], "pver": pv["package_version"]}
        )

    # Step 4: Enterprise Topology Ingestion
    print("[5/5] Inserting Enterprise Topology (Services, Teams, DataStores, Calls, Reads)...")
    teams, datastores, services, reads_edges, call_edges, pkg_deps = build_enterprise_topology()

    for t in teams:
        graph.query("MERGE (t:Team {name: $name})", {"name": t["name"]})

    for d in datastores:
        graph.query(
            "MERGE (d:DataStore {name: $name}) SET d.sensitivity = $sensitivity",
            {"name": d["name"], "sensitivity": d["sensitivity"]}
        )

    for s in services:
        graph.query(
            "MERGE (s:Service {name: $name}) SET s.internet_facing = $internet_facing",
            {"name": s["name"], "internet_facing": s["internet_facing"]}
        )
        graph.query(
            "MATCH (t:Team {name: $tname}), (s:Service {name: $sname}) "
            "MERGE (t)-[:OWNS]->(s)",
            {"tname": s["team"], "sname": s["name"]}
        )

    for s_name, pkgs in service_packages.items():
        for p in pkgs:
            graph.query(
                "MATCH (s:Service {name: $sname}), (p:Package {name: $pname, version: $pver}) "
                "MERGE (s)-[:DEPENDS_ON]->(p)",
                {"sname": s_name, "pname": p["name"], "pver": p["version"]}
            )

    # Package transitive dependencies
    for (p1_name, p1_ver), (p2_name, p2_ver) in pkg_deps:
        graph.query(
            "MATCH (p1:Package {name: $p1_name, version: $p1_ver}), "
            "      (p2:Package {name: $p2_name, version: $p2_ver}) "
            "MERGE (p1)-[:DEPENDS_ON]->(p2)",
            {"p1_name": p1_name, "p1_ver": p1_ver, "p2_name": p2_name, "p2_ver": p2_ver}
        )

    # Service -> CALLS -> Service
    for src, dst in call_edges:
        graph.query(
            "MATCH (s1:Service {name: $src}), (s2:Service {name: $dst}) "
            "MERGE (s1)-[:CALLS]->(s2)",
            {"src": src, "dst": dst}
        )

    # Service -> READS -> DataStore
    for svc, ds in reads_edges:
        graph.query(
            "MATCH (s:Service {name: $sname}), (d:DataStore {name: $dname}) "
            "MERGE (s)-[:READS]->(d)",
            {"sname": svc, "dname": ds}
        )

    # Step 6: Seed Past Decisions for `similar_past_decisions` Cypher context
    print("      Seeding past triage decisions for historical graph similarity...")
    past_decisions = [
        {
            "id": "dec-hist-001",
            "verdict": "patch_immediately",
            "risk": 8.8,
            "ts": 1728000000,
            "status": "approved",
            "action_type": "ticket_jira",
            "rationale": "High-risk path to payment data via internet ingress",
            "vuln_id": "CVE-2023-SLEEPER-01",
            "service": "checkout-service"
        },
        {
            "id": "dec-hist-002",
            "verdict": "deprioritize",
            "risk": 1.5,
            "ts": 1727000000,
            "status": "approved",
            "action_type": "log_only",
            "rationale": "Unreachable internal tool with no path to sensitive data",
            "vuln_id": "CVE-2021-DECOY-01",
            "service": "internal-dev-tool"
        }
    ]

    for dec in past_decisions:
        graph.query(
            "MERGE (d:Decision {id: $id}) "
            "SET d.verdict = $verdict, d.risk = $risk, d.ts = $ts, "
            "    d.status = $status, d.action_type = $action_type, d.rationale = $rationale",
            {
                "id": dec["id"],
                "verdict": dec["verdict"],
                "risk": dec["risk"],
                "ts": dec["ts"],
                "status": dec["status"],
                "action_type": dec["action_type"],
                "rationale": dec["rationale"],
            }
        )
        graph.query(
            "MATCH (d:Decision {id: $did}), (v:Vuln {id: $vid}) MERGE (d)-[:BASED_ON]->(v)",
            {"did": dec["id"], "vid": dec["vuln_id"]}
        )
        graph.query(
            "MATCH (d:Decision {id: $did}), (s:Service {name: $sname}) MERGE (d)-[:ABOUT]->(s)",
            {"did": dec["id"], "sname": dec["service"]}
        )

    # Verification counts
    print("\n" + "=" * 60)
    print("INGESTION COMPLETED - FALKORDB GRAPH VERIFICATION COUNTS")
    print("=" * 60)

    node_labels = ["Vuln", "Package", "Service", "DataStore", "Team", "Decision"]
    total_nodes = 0
    for label in node_labels:
        res = graph.query(f"MATCH (n:{label}) RETURN count(n) AS cnt")
        cnt = res.result_set[0][0]
        total_nodes += cnt
        print(f"  • Node Label :{label:<12} -> {cnt:>3} nodes")

    print(f"  ---------------------------------")
    print(f"  • Total Graph Nodes         -> {total_nodes:>3} nodes\n")

    rel_types = ["AFFECTS", "DEPENDS_ON", "CALLS", "READS", "OWNS", "BASED_ON", "ABOUT"]
    total_edges = 0
    for rtype in rel_types:
        res = graph.query(f"MATCH ()-[r:{rtype}]->() RETURN count(r) AS cnt")
        cnt = res.result_set[0][0]
        total_edges += cnt
        print(f"  • Relationship :{rtype:<12} -> {cnt:>3} edges")

    print(f"  ---------------------------------")
    print(f"  • Total Graph Edges         -> {total_edges:>3} edges")
    print("=" * 60)


if __name__ == "__main__":
    import sys
    if "--check-osv" in sys.argv:
        check_osv_fetch()
    else:
        ingest_all()
