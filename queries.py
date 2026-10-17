"""
VulnGraph Cypher Query & Graph Algorithm Module.

All read queries execute via `graph.ro_query` with parameterized inputs and row caps.
All algorithms use native FalkorDB procedures (e.g. `algo.pageRank`).
All writes create staged Decision nodes with status 'pending' (human-in-the-loop).
"""

import time
import uuid
import json
from typing import Dict, List, Any

from schema import get_graph

EXPOSURE_FLOOR = 0.15
FORMULA_VERSION = "v1.2.0"


def get_finding_context(vuln_id: str) -> Dict[str, Any]:
    """
    Retrieves full finding details (CVSS, summary, fix_version) along with
    affected package(s) and directly dependent services.
    """
    graph = get_graph()
    cypher = """
    MATCH (v:Vuln {id: $vuln_id})-[:AFFECTS]->(p:Package)
    OPTIONAL MATCH (s:Service)-[:DEPENDS_ON]->(p)
    RETURN v.id AS vuln_id,
           v.cvss AS cvss,
           v.summary AS summary,
           v.fix_version AS fix_version,
           p.name AS package_name,
           p.version AS package_version,
           collect(DISTINCT s.name) AS direct_services
    LIMIT 25
    """
    res = graph.ro_query(cypher, {"vuln_id": vuln_id})
    if not res.result_set:
        return {"vuln_id": vuln_id, "found": False, "error": f"Vulnerability {vuln_id} not found"}

    rows = res.result_set
    first = rows[0]
    packages = []
    direct_services = set()
    for row in rows:
        packages.append({"name": row[4], "version": row[5]})
        if row[6]:
            direct_services.update(row[6])

    return {
        "vuln_id": first[0],
        "found": True,
        "cvss": float(first[1]),
        "summary": first[2],
        "fix_version": first[3],
        "packages": packages,
        "direct_services": sorted(list(direct_services))
    }


def blast_radius(vuln_id: str) -> Dict[str, Any]:
    """
    Computes multi-hop blast radius without path explosion:
      1. Distinct cheap impact discovery: who is impacted.
      2. Single clean explanatory chain per service via shortestPath.
    """
    graph = get_graph()

    # Step 1: Distinct cheap impact discovery
    distinct_cypher = """
    MATCH (v:Vuln {id: $vuln_id})-[:AFFECTS]->(p:Package)
    MATCH (s:Service)-[:DEPENDS_ON*1..6]->(p)
    RETURN DISTINCT s.name AS service, s.internet_facing AS internet_facing
    LIMIT 25
    """
    res = graph.ro_query(distinct_cypher, {"vuln_id": vuln_id})
    impacted_services = []
    has_internet_facing = False

    for row in res.result_set:
        svc_name, internet_facing = row[0], bool(row[1])
        impacted_services.append(svc_name)
        if internet_facing:
            has_internet_facing = True

    # Step 2: Fetch one explanatory chain per service with shortestPath
    chains = []
    for svc in impacted_services[:10]:
        sp_cypher = """
        MATCH (s:Service {name: $svc}), (p:Package)<-[:AFFECTS]-(v:Vuln {id: $vuln_id})
        WITH s, p, shortestPath((s)-[:DEPENDS_ON*1..6]->(p)) AS sp
        WHERE sp IS NOT NULL
        RETURN [n in nodes(sp) | coalesce(n.name, n.id)] AS chain
        LIMIT 1
        """
        res_sp = graph.ro_query(sp_cypher, {"svc": svc, "vuln_id": vuln_id})
        if res_sp.result_set:
            chains.append({"service": svc, "chain": res_sp.result_set[0][0]})
        else:
            chains.append({"service": svc, "chain": [svc, vuln_id]})

    return {
        "vuln_id": vuln_id,
        "impacted_service_count": len(impacted_services),
        "impacted_services": sorted(impacted_services),
        "has_internet_facing": has_internet_facing,
        "dependency_chains": chains
    }


def exploit_path(service: str) -> Dict[str, Any]:
    """
    Evaluates whether an internet-facing attacker can reach the service,
    and whether the service can reach high- or medium-sensitivity DataStores.
    Uses FalkorDB's native shortestPath() in WITH clauses.
    """
    graph = get_graph()

    # 1. Ingress path: Internet-facing entry to this service
    ingress_cypher = """
    MATCH (ingress:Service {internet_facing: true}), (s:Service {name: $service})
    WITH ingress, s, shortestPath((ingress)-[:CALLS*0..5]->(s)) AS p_in
    WHERE p_in IS NOT NULL
    RETURN [n in nodes(p_in) | n.name] AS ingress_path, ingress.name AS ingress_service
    LIMIT 5
    """
    res_in = graph.ro_query(ingress_cypher, {"service": service})
    ingress_paths = []
    is_internet_exposed = False
    for row in res_in.result_set:
        ingress_paths.append(row[0])
        is_internet_exposed = True

    # 2. Egress path: Service to sensitive DataStores
    egress_cypher = """
    MATCH (s:Service {name: $service}), (target:Service)-[:READS]->(d:DataStore)
    WITH s, target, d, shortestPath((s)-[:CALLS*0..5]->(target)) AS p_out
    WHERE p_out IS NOT NULL
    RETURN [n in nodes(p_out) | n.name] AS call_path, d.name AS datastore, d.sensitivity AS sensitivity
    ORDER BY CASE d.sensitivity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END ASC
    LIMIT 5
    """
    res_out = graph.ro_query(egress_cypher, {"service": service})
    sensitive_data_paths = []
    max_sensitivity = "none"

    for row in res_out.result_set:
        call_chain, ds_name, sensitivity = row[0], row[1], row[2]
        sensitive_data_paths.append({
            "call_chain": call_chain,
            "datastore": ds_name,
            "sensitivity": sensitivity
        })
        if sensitivity == "high":
            max_sensitivity = "high"
        elif sensitivity == "medium" and max_sensitivity != "high":
            max_sensitivity = "medium"
        elif sensitivity == "low" and max_sensitivity == "none":
            max_sensitivity = "low"

    has_exploit_chain = is_internet_exposed and max_sensitivity in ("high", "medium")

    return {
        "service": service,
        "is_internet_exposed": is_internet_exposed,
        "ingress_paths": ingress_paths,
        "max_data_sensitivity": max_sensitivity,
        "data_paths": sensitive_data_paths,
        "has_critical_exploit_path": has_exploit_chain
    }


def rank_critical_packages(limit: int = 25) -> List[Dict[str, Any]]:
    """
    Executes FalkorDB's native PageRank algorithm over Package nodes connected
    by DEPENDS_ON edges to discover structural package criticality.
    """
    graph = get_graph()
    cypher = """
    CALL algo.pageRank('Package', 'DEPENDS_ON')
    YIELD node, score
    RETURN node.name AS package_name, node.version AS version, score
    ORDER BY score DESC
    LIMIT $limit
    """
    res = graph.ro_query(cypher, {"limit": min(limit, 25)})
    results = []
    for row in res.result_set:
        results.append({
            "package_name": row[0],
            "version": row[1],
            "pagerank_score": round(float(row[2]), 6)
        })
    return results


def find_owner(service: str) -> Dict[str, Any]:
    """
    Looks up the team that owns the service, plus other services in their purview.
    """
    graph = get_graph()
    cypher = """
    MATCH (t:Team)-[:OWNS]->(s:Service {name: $service})
    OPTIONAL MATCH (t)-[:OWNS]->(other:Service)
    RETURN t.name AS team_name, collect(DISTINCT other.name) AS all_owned_services
    LIMIT 25
    """
    res = graph.ro_query(cypher, {"service": service})
    if not res.result_set:
        return {"service": service, "found": False, "team": "unknown"}

    row = res.result_set[0]
    return {
        "service": service,
        "found": True,
        "team": row[0],
        "all_owned_services": sorted(row[1]) if row[1] else [service]
    }


def similar_past_decisions(vuln_id: str) -> List[Dict[str, Any]]:
    """
    Queries past triage decisions for the given vulnerability ID or on services
    impacted by the vulnerability for historical graph context.
    """
    graph = get_graph()
    # 1. Direct matches on vuln_id
    cypher_direct = """
    MATCH (d:Decision)-[:BASED_ON]->(v:Vuln {id: $vuln_id})
    OPTIONAL MATCH (d)-[:ABOUT]->(s:Service)
    RETURN d.id AS decision_id,
           d.verdict AS verdict,
           d.risk AS risk,
           d.status AS status,
           d.action_type AS action_type,
           d.rationale AS rationale,
           d.ts AS timestamp,
           s.name AS service
    ORDER BY CASE WHEN d.status = 'approved' THEN 1 ELSE 2 END ASC, d.ts DESC
    LIMIT 25
    """
    res_direct = graph.ro_query(cypher_direct, {"vuln_id": vuln_id})
    decisions = []
    seen = set()

    for row in res_direct.result_set:
        did = row[0]
        seen.add(did)
        decisions.append({
            "decision_id": did,
            "verdict": row[1],
            "risk": float(row[2]) if row[2] is not None else None,
            "status": row[3],
            "action_type": row[4],
            "rationale": row[5],
            "timestamp": row[6],
            "service": row[7],
            "match_type": "direct_vuln"
        })

    # 2. Service-level past decisions
    cypher_svc = """
    MATCH (v:Vuln {id: $vuln_id})-[:AFFECTS]->(p:Package)<-[:DEPENDS_ON*1..4]-(s:Service)<-[:ABOUT]-(d:Decision)
    WHERE NOT d.id IN $seen
    RETURN DISTINCT d.id AS decision_id,
           d.verdict AS verdict,
           d.risk AS risk,
           d.status AS status,
           d.action_type AS action_type,
           d.rationale AS rationale,
           d.ts AS timestamp,
           s.name AS service
    ORDER BY d.ts DESC
    LIMIT 25
    """
    res_svc = graph.ro_query(cypher_svc, {"vuln_id": vuln_id, "seen": list(seen)})
    for row in res_svc.result_set:
        decisions.append({
            "decision_id": row[0],
            "verdict": row[1],
            "risk": float(row[2]) if row[2] is not None else None,
            "status": row[3],
            "action_type": row[4],
            "rationale": row[5],
            "timestamp": row[6],
            "service": row[7],
            "match_type": "related_service"
        })

    return decisions[:25]


def compute_risk(vuln_id: str) -> Dict[str, Any]:
    """
    Deterministic graph-aware risk score computation:
      score = 10.0 * (cvss_norm * exposure * data_sensitivity * blast_radius_factor)
    All components are returned individually for full explainability.
    """
    finding = get_finding_context(vuln_id)
    if not finding.get("found"):
        return {"vuln_id": vuln_id, "error": f"Vulnerability {vuln_id} not found"}

    cvss_raw = finding["cvss"]
    # cvss_norm normalized to range [0.5, 1.0] so baseline severity matters but graph topology decides rank
    cvss_norm = round(0.5 + 0.5 * (cvss_raw / 10.0), 4)

    # Blast radius & internet exposure evaluation
    radius = blast_radius(vuln_id)
    impacted_services = radius["impacted_services"]
    has_direct_internet = radius["has_internet_facing"]

    # Ingress and data sensitivity analysis across all impacted services
    max_data_sensitivity = "none"
    is_ingress_reachable = has_direct_internet
    evidence_paths = []

    for svc in impacted_services:
        ep = exploit_path(svc)
        if ep["is_internet_exposed"]:
            is_ingress_reachable = True
        if ep["max_data_sensitivity"] == "high":
            max_data_sensitivity = "high"
        elif ep["max_data_sensitivity"] == "medium" and max_data_sensitivity != "high":
            max_data_sensitivity = "medium"
        elif ep["max_data_sensitivity"] == "low" and max_data_sensitivity == "none":
            max_data_sensitivity = "low"

        for dp in ep["data_paths"]:
            evidence_paths.append(f"{svc} -> {' -> '.join(dp['call_chain'])} -> DataStore({dp['datastore']}, {dp['sensitivity']})")

    # Exposure factor
    if has_direct_internet:
        exposure = 1.0
    elif is_ingress_reachable:
        exposure = 0.75
    else:
        exposure = 0.20

    # Effective exposure with exposure floor for incomplete graph topologies
    effective_exposure = max(exposure, EXPOSURE_FLOOR)

    # Data sensitivity factor
    if max_data_sensitivity == "high":
        data_sensitivity = 1.0
    elif max_data_sensitivity == "medium":
        data_sensitivity = 0.60
    elif max_data_sensitivity == "low":
        data_sensitivity = 0.25
    else:
        data_sensitivity = 0.20

    # Blast radius factor (scales with count of impacted services)
    svc_count = len(impacted_services)
    blast_radius_factor = round(min(1.0, 0.6 + 0.1 * max(0, svc_count - 1)), 2)

    # Critical path weight: Internet ingress with path to high-sensitivity crown jewels
    critical_path_multiplier = 1.6 if (is_ingress_reachable and max_data_sensitivity == "high") else 1.0

    # Graph risk score (0.0 to 10.0 scale)
    raw_score = 10.0 * (cvss_norm * effective_exposure * data_sensitivity * blast_radius_factor) * critical_path_multiplier
    graph_risk = round(min(10.0, raw_score), 2)

    # Confidence score (0.0 - 1.0 scale):
    # Drops when node has low degree (sparse topology), path relies on unverified edges, or finding is old.
    confidence = 1.0
    if len(impacted_services) == 0:
        confidence -= 0.30
    elif len(impacted_services) == 1:
        confidence -= 0.10

    if not is_ingress_reachable:
        confidence -= 0.10

    # Age penalty: extract publication year if present in CVE ID (e.g. CVE-2021-...)
    if "CVE-" in vuln_id:
        try:
            year_part = vuln_id.split("-")[1]
            if year_part.isdigit():
                cve_year = int(year_part)
                if cve_year <= 2022:
                    confidence -= 0.05
        except Exception:
            pass

    confidence = round(max(0.30, min(1.0, confidence)), 2)

    # Suggested verdict based on deterministic score
    if graph_risk >= 7.0:
        verdict = "patch_immediately"
    elif graph_risk >= 4.0:
        verdict = "schedule_maintenance"
    else:
        verdict = "deprioritize"

    return {
        "vuln_id": vuln_id,
        "cvss_raw": cvss_raw,
        "components": {
            "cvss_norm": cvss_norm,
            "exposure": exposure,
            "effective_exposure": effective_exposure,
            "data_sensitivity": data_sensitivity,
            "blast_radius_factor": blast_radius_factor,
            "critical_path_multiplier": critical_path_multiplier,
            "formula_version": FORMULA_VERSION,
        },
        "graph_risk_score": graph_risk,
        "confidence": confidence,
        "formula_version": FORMULA_VERSION,
        "verdict": verdict,
        "impacted_services": impacted_services,
        "has_internet_exposure": is_ingress_reachable,
        "max_data_sensitivity": max_data_sensitivity,
        "evidence_paths": evidence_paths[:5]
    }


def propose_action(vuln_id: str, action_type: str, rationale: str, evidence: List[str]) -> Dict[str, Any]:
    """
    STAGED WRITE ONLY: Writes a Decision node with status 'pending'.
    The LLM cannot execute actions directly. Human approval via POST /approve/{decision_id} is required.
    """
    graph = get_graph()
    decision_id = f"dec-{uuid.uuid4().hex[:8]}"
    ts = int(time.time())

    # Calculate deterministic risk score for Decision node
    risk_data = compute_risk(vuln_id)
    risk_score = risk_data.get("graph_risk_score", 5.0)
    confidence = risk_data.get("confidence", 0.90)
    formula_version = risk_data.get("formula_version", FORMULA_VERSION)

    # Find the primary service impacted
    finding = get_finding_context(vuln_id)
    impacted = finding.get("direct_services", [])
    primary_svc = impacted[0] if impacted else "unknown-service"

    evidence_json = json.dumps(evidence) if isinstance(evidence, list) else str(evidence)

    cypher = """
    MATCH (v:Vuln {id: $vuln_id})
    CREATE (d:Decision {
        id: $id,
        verdict: $action_type,
        risk: $risk,
        confidence: $confidence,
        formula_version: $formula_version,
        ts: $ts,
        status: 'pending',
        action_type: $action_type,
        rationale: $rationale,
        evidence: $evidence
    })
    CREATE (d)-[:BASED_ON]->(v)
    WITH d
    OPTIONAL MATCH (s:Service {name: $service})
    FOREACH (_ IN CASE WHEN s IS NOT NULL THEN [1] ELSE [] END |
        CREATE (d)-[:ABOUT]->(s)
    )
    RETURN d.id AS decision_id, d.status AS status
    """

    graph.query(cypher, {
        "vuln_id": vuln_id,
        "id": decision_id,
        "action_type": action_type,
        "risk": float(risk_score),
        "confidence": float(confidence),
        "formula_version": formula_version,
        "ts": ts,
        "rationale": rationale,
        "evidence": evidence_json,
        "service": primary_svc
    })

    return {
        "decision_id": decision_id,
        "status": "pending",
        "vuln_id": vuln_id,
        "action_type": action_type,
        "service": primary_svc,
        "risk": risk_score,
        "confidence": confidence,
        "formula_version": formula_version,
        "message": f"Action staged successfully with ID '{decision_id}'. Requires human approval before execution."
    }
