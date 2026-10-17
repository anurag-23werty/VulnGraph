"""
Test suite for VulnGraph FastAPI backend endpoints.
Verifies /health, /findings, /triage, /baseline, /graph/path, /approve/{id}, /tickets, and static UI.
"""

import sys
from pathlib import Path
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from main import app
from schema import get_graph
import queries

client = TestClient(app)


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["database"] == "FalkorDB"
    assert data["graph_nodes"] > 0


def test_serve_ui_index():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "VulnGraph" in resp.text
    assert 'id="root"' in resp.text


def test_list_findings():
    resp = client.get("/findings?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] > 0
    assert "findings" in data
    # Ensure finding has required properties
    sample = data["findings"][0]
    assert "vuln_id" in sample
    assert "cvss" in sample
    assert "package" in sample


def test_baseline_endpoint():
    resp = client.get("/baseline?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] > 0
    rankings = data["rankings"]
    # Verify rankings are strictly sorted by CVSS descending
    for i in range(len(rankings) - 1):
        assert rankings[i]["cvss"] >= rankings[i + 1]["cvss"]


def test_graph_path_general():
    resp = client.get("/graph/path")
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data and len(data["nodes"]) > 0
    assert "links" in data and len(data["links"]) > 0
    assert data["highlighted_node_count"] == 0


def test_graph_path_highlighted():
    resp = client.get("/graph/path?vuln_id=CVE-2023-SLEEPER-01")
    assert resp.status_code == 200
    data = resp.json()
    assert data["vuln_id"] == "CVE-2023-SLEEPER-01"
    assert data["highlighted_node_count"] > 0
    # Verify at least one node and link has highlight=True
    assert any(n.get("highlight") is True for n in data["nodes"])
    assert any(link.get("highlight") is True for link in data["links"])


def test_post_triage_benchmark():
    payload = {
        "vuln_ids": [
            "CVE-2023-SLEEPER-01",
            "CVE-2021-DECOY-01"
        ]
    }
    resp = client.post("/triage", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert "report" in data
    assert "trace" in data
    assert "baseline_ranking" in data
    assert "graph_ranking" in data

    # Verify reordering
    assert data["baseline_ranking"][0]["vuln_id"] == "CVE-2021-DECOY-01"
    assert data["graph_ranking"][0]["vuln_id"] == "CVE-2023-SLEEPER-01"


def test_approve_decision_flow():
    # 1. First stage a new proposal
    staged = queries.propose_action(
        vuln_id="CVE-2023-SLEEPER-02",
        action_type="patch_immediately",
        rationale="Internet-exposed JWT signature vulnerability reading user credentials.",
        evidence=["auth-service -> user-credentials-store"]
    )
    decision_id = staged["decision_id"]

    # 2. Call approval endpoint
    resp = client.post(f"/approve/{decision_id}")
    assert resp.status_code == 200
    res_data = resp.json()

    assert res_data["status"] == "dispatched"
    assert "ticket_id" in res_data
    assert res_data["ticket_id"].startswith("TICK-")
    assert res_data["decision_id"] == decision_id

    # 3. Verify in FalkorDB directly that status is 'dispatched'
    g = get_graph()
    q_check = "MATCH (d:Decision {id: $id}) RETURN d.status, d.approved_by"
    db_res = g.query(q_check, {"id": decision_id})
    assert db_res.result_set[0][0] == "dispatched"
    assert db_res.result_set[0][1] is not None

    # 4. Double-approval test: attempting to approve again must return 409 Conflict
    double_resp = client.post(f"/approve/{decision_id}")
    assert double_resp.status_code == 409

    # 5. Check /tickets endpoint to ensure ticket was recorded in tickets.jsonl
    tickets_resp = client.get("/tickets")
    assert tickets_resp.status_code == 200
    tickets_data = tickets_resp.json()
    assert tickets_data["count"] > 0
    assert any(t["decision_id"] == decision_id for t in tickets_data["tickets"])


def test_reject_decision_flow():
    """Verify atomic rejection state transition and feedback recording."""
    # 1. Stage a proposal
    staged = queries.propose_action(
        vuln_id="CVE-2021-DECOY-01",
        action_type="deprioritize",
        rationale="Internal offline analytics service with zero ingress paths.",
        evidence=[]
    )
    decision_id = staged["decision_id"]

    # 2. Reject with mandatory reason
    resp = client.post(f"/reject/{decision_id}", json={"reason": "Compensating controls insufficient; requires maintenance window."})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "rejected"
    assert data["decision_id"] == decision_id

    # 3. Verify in FalkorDB
    g = get_graph()
    db_res = g.ro_query("MATCH (d:Decision {id: $id}) RETURN d.status, d.rejection_reason", {"id": decision_id})
    assert db_res.result_set[0][0] == "rejected"
    assert "Compensating controls" in db_res.result_set[0][1]

    # 4. Attempting to approve or reject again must return 409 Conflict
    conflict_resp = client.post(f"/reject/{decision_id}", json={"reason": "duplicate rejection"})
    assert conflict_resp.status_code == 409


def test_findings_enhanced_contract():
    """Verifies that GET /findings returns all properties specified in frontend contract."""
    resp = client.get("/findings?limit=5")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] > 0
    f = data["findings"][0]
    # Required keys per backend contract
    assert "id" in f
    assert "package" in f
    assert "service" in f
    assert "owner" in f
    assert "verdict" in f
    assert "risk" in f
    assert "confidence" in f
    assert "formula_version" in f
    assert "components" in f
    comps = f["components"]
    assert "cvss_norm" in comps
    assert "exposure" in comps
    assert "sensitivity" in comps
    assert "blast" in comps


def test_trace_endpoint():
    """Verifies GET /trace/{vuln_id} returns ordered tool calls with duration and cypher."""
    resp = client.get("/trace/CVE-2023-SLEEPER-01")
    assert resp.status_code == 200
    data = resp.json()
    assert data["vuln_id"] == "CVE-2023-SLEEPER-01"
    assert "steps" in data
    assert len(data["steps"]) >= 4
    step1 = data["steps"][0]
    assert "name" in step1
    assert "args" in step1
    assert "duration_ms" in step1
    assert "result_summary" in step1
    assert "cypher" in step1


def test_tools_catalog_and_run():
    """Verifies GET /tools and POST /tools/{name}/run on allowlisted read tools."""
    resp = client.get("/tools")
    assert resp.status_code == 200
    catalog = resp.json()
    assert "tools" in catalog
    tool_names = [t["name"] for t in catalog["tools"]]
    assert "get_finding_context" in tool_names
    assert "blast_radius" in tool_names
    assert "propose_action" not in tool_names  # Staged write tool must NOT be in read tools

    # Test running allowlisted read tool
    run_resp = client.post("/tools/get_finding_context/run", json={"args": {"vuln_id": "CVE-2023-SLEEPER-01"}})
    assert run_resp.status_code == 200
    run_data = run_resp.json()
    assert run_data["tool"] == "get_finding_context"
    assert "duration_ms" in run_data
    assert run_data["result"]["found"] is True

    # Test rejecting non-allowlisted tool
    bad_resp = client.post("/tools/propose_action/run", json={"args": {}})
    assert bad_resp.status_code == 403


def test_decisions_endpoint():
    """Verifies GET /decisions lists decisions grouped with counts."""
    resp = client.get("/decisions")
    assert resp.status_code == 200
    data = resp.json()
    assert "counts" in data
    assert "decisions" in data
    assert "total" in data
    assert data["total"] >= 0


def test_eval_latest_endpoint():
    """Verifies GET /eval/latest returns ablation, KEV validation, and planted scenarios."""
    resp = client.get("/eval/latest")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "planted_scenarios" in data
    assert "ablation" in data
    assert "kev_validation" in data
    assert "sensitivity" in data
    assert "what_this_does_not_do" in data
    assert data["kev_validation"]["status"] == "VALIDATED"
    assert data["planted_scenarios"]["inversion_success"] is True
