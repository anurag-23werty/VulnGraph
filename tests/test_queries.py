"""
Comprehensive pytest test suite for VulnGraph Cypher queries and graph algorithms.
Tests all functions in queries.py against the planted enterprise graph data in FalkorDB.
"""

import pytest
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from schema import get_graph
from queries import (
    get_finding_context,
    blast_radius,
    exploit_path,
    rank_critical_packages,
    find_owner,
    similar_past_decisions,
    compute_risk,
    propose_action
)


@pytest.fixture(scope="session")
def graph_conn():
    g = get_graph()
    # Verify graph exists and is populated
    res = g.query("MATCH (n) RETURN count(n)")
    count = res.result_set[0][0]
    assert count > 0, "FalkorDB graph is empty! Run ingest.py first."
    return g


def test_get_finding_context_existing():
    ctx = get_finding_context("CVE-2023-SLEEPER-01")
    assert ctx["found"] is True
    assert ctx["vuln_id"] == "CVE-2023-SLEEPER-01"
    assert ctx["cvss"] == 5.3
    assert ctx["fix_version"] == "1.26.5"
    assert len(ctx["packages"]) >= 1
    assert any(p["name"] == "urllib3" for p in ctx["packages"])
    assert "checkout-service" in ctx["direct_services"]


def test_get_finding_context_nonexistent():
    ctx = get_finding_context("CVE-NON-EXISTENT-9999")
    assert ctx["found"] is False


def test_blast_radius_multi_hop():
    # SLEEPER-03 (lodash) is depended on transitively: api-gateway -> express -> lodash
    radius = blast_radius("CVE-2023-SLEEPER-03")
    assert radius["impacted_service_count"] >= 1
    assert "api-gateway" in radius["impacted_services"]
    assert radius["has_internet_facing"] is True

    # Check that a chain was returned containing the hops
    chains = radius["dependency_chains"]
    assert len(chains) > 0
    gateway_chains = [c["chain"] for c in chains if c["service"] == "api-gateway"]
    assert any("lodash" in ch for ch in gateway_chains)


def test_exploit_path_internet_exposed():
    # checkout-service is internet_facing and calls payment-service -> payment-vault (high)
    ep = exploit_path("checkout-service")
    assert ep["is_internet_exposed"] is True
    assert ep["max_data_sensitivity"] == "high"
    assert ep["has_critical_exploit_path"] is True
    assert any(dp["datastore"] == "payment-vault" for dp in ep["data_paths"])


def test_exploit_path_unreachable_internal():
    # internal-dev-tool has no internet-facing ingress and reads only low-sensitivity audit-archive
    ep = exploit_path("internal-dev-tool")
    assert ep["is_internet_exposed"] is False
    assert len(ep["ingress_paths"]) == 0
    assert ep["max_data_sensitivity"] == "low"
    assert ep["has_critical_exploit_path"] is False


def test_rank_critical_packages_pagerank():
    ranked = rank_critical_packages(limit=10)
    assert isinstance(ranked, list)
    assert len(ranked) > 0
    top = ranked[0]
    assert "package_name" in top
    assert "version" in top
    assert "pagerank_score" in top
    assert top["pagerank_score"] > 0.0


def test_find_owner():
    # checkout-service is owned by checkout-squad
    owner = find_owner("checkout-service")
    assert owner["found"] is True
    assert owner["team"] == "checkout-squad"
    assert "payment-service" in owner["all_owned_services"]

    # auth-service is owned by identity-team
    owner_auth = find_owner("auth-service")
    assert owner_auth["found"] is True
    assert owner_auth["team"] == "identity-team"


def test_similar_past_decisions():
    decisions = similar_past_decisions("CVE-2023-SLEEPER-01")
    assert isinstance(decisions, list)
    assert len(decisions) >= 1
    # Check that dec-hist-001 was found
    hist = next((d for d in decisions if d["decision_id"] == "dec-hist-001"), None)
    assert hist is not None
    assert hist["verdict"] == "patch_immediately"
    assert hist["status"] == "approved"


def test_compute_risk_components_and_explainability():
    risk = compute_risk("CVE-2023-SLEEPER-01")
    assert "graph_risk_score" in risk
    assert "components" in risk
    comps = risk["components"]
    assert "cvss_norm" in comps
    assert "exposure" in comps
    assert "data_sensitivity" in comps
    assert "blast_radius_factor" in comps

    # Sleeper 01 is internet exposed with high sensitivity data
    assert comps["exposure"] == 1.0
    assert comps["data_sensitivity"] == 1.0
    assert risk["verdict"] in ("patch_immediately", "schedule_maintenance")
    assert len(risk["evidence_paths"]) > 0


def test_propose_action_staged_only(graph_conn):
    # Proposing an action must create a Decision with status 'pending'
    res = propose_action(
        vuln_id="CVE-2023-SLEEPER-02",
        action_type="patch_immediately",
        rationale="Auth token forgery vulnerability exposed to internet ingress reading user credentials.",
        evidence=["auth-service -> user-credentials-store (high)"]
    )

    assert "decision_id" in res
    assert res["status"] == "pending"
    decision_id = res["decision_id"]

    # Verify directly in FalkorDB that node was created with status 'pending'
    check_q = "MATCH (d:Decision {id: $id}) RETURN d.status, d.action_type, d.verdict"
    db_res = graph_conn.query(check_q, {"id": decision_id})
    assert len(db_res.result_set) == 1
    assert db_res.result_set[0][0] == "pending"
    assert db_res.result_set[0][1] == "patch_immediately"


def test_valid_scoring_properties(graph_conn):
    # 1. Exposure floor test
    risk = compute_risk("CVE-2021-DECOY-01")
    assert "effective_exposure" in risk["components"]
    assert risk["components"]["effective_exposure"] >= 0.15
    assert risk["graph_risk_score"] > 0.0

    # 2. Confidence score test
    sleeper_risk = compute_risk("CVE-2023-SLEEPER-01")
    decoy_risk = compute_risk("CVE-2021-DECOY-01")
    assert "confidence" in sleeper_risk
    assert "confidence" in decoy_risk
    assert 0.3 <= sleeper_risk["confidence"] <= 1.0
    assert 0.3 <= decoy_risk["confidence"] <= 1.0
    # Sleeper with verified ingress & active degree has higher confidence than old, unexposed decoy
    assert sleeper_risk["confidence"] > decoy_risk["confidence"]

    # 3. Formula version on Decision node
    res = propose_action(
        vuln_id="CVE-2023-SLEEPER-03",
        action_type="patch_immediately",
        rationale="Testing formula versioning on Decision node.",
        evidence=["ingress -> payments-db"]
    )
    assert res["formula_version"] == "v1.2.0"
    assert "confidence" in res

    check_q = "MATCH (d:Decision {id: $id}) RETURN d.formula_version, d.confidence"
    db_res = graph_conn.query(check_q, {"id": res["decision_id"]})
    assert len(db_res.result_set) == 1
    assert db_res.result_set[0][0] == "v1.2.0"
    assert db_res.result_set[0][1] is not None


def test_ground_truth_graph_reordering():
    """
    CRUCIAL HACKATHON EVALUATION TEST:
    Proves that graph traversal reorders findings compared to naive CVSS ranking.
    - CVSS ranking alone puts Decoys (9.6 - 9.8) at top, Sleepers (5.3 - 6.1) at bottom.
    - Graph-aware risk score inverts this: Sleepers have higher risk than Decoys.
    """
    sleepers = ["CVE-2023-SLEEPER-01", "CVE-2023-SLEEPER-02", "CVE-2023-SLEEPER-03"]
    decoys = ["CVE-2021-DECOY-01", "CVE-2022-DECOY-02", "CVE-2023-DECOY-03"]

    sleeper_risks = [compute_risk(sid) for sid in sleepers]
    decoy_risks = [compute_risk(did) for did in decoys]

    # Verify raw CVSS: Decoys > Sleepers
    min_decoy_cvss = min(d["cvss_raw"] for d in decoy_risks)
    max_sleeper_cvss = max(s["cvss_raw"] for s in sleeper_risks)
    assert min_decoy_cvss > max_sleeper_cvss, "Raw CVSS condition failed: Decoys must have higher CVSS"

    # Verify Graph-Aware Risk: ALL Sleepers > ALL Decoys
    min_sleeper_graph_risk = min(s["graph_risk_score"] for s in sleeper_risks)
    max_decoy_graph_risk = max(d["graph_risk_score"] for d in decoy_risks)

    print("\n--- GROUND TRUTH REORDERING PROOF ---")
    print("SLEEPERS (Medium CVSS -> High Graph Risk):")
    for s in sleeper_risks:
        print(f"  {s['vuln_id']}: CVSS {s['cvss_raw']} -> Graph Risk: {s['graph_risk_score']} ({s['verdict']})")

    print("DECOYS (Critical CVSS -> Low Graph Risk):")
    for d in decoy_risks:
        print(f"  {d['vuln_id']}: CVSS {d['cvss_raw']} -> Graph Risk: {d['graph_risk_score']} ({d['verdict']})")

    assert min_sleeper_graph_risk > max_decoy_graph_risk, (
        f"Graph reordering failed! Min Sleeper ({min_sleeper_graph_risk}) "
        f"must be higher than Max Decoy ({max_decoy_graph_risk})"
    )
