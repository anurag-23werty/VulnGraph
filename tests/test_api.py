"""
Test suite for VulnGraph FastAPI backend endpoints.
Verifies /health, /findings, /triage, /baseline, /graph/path, /approve/{id}, /tickets, and static UI.
"""

import os
import sys
import json
import pytest
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
    assert "force-graph" in resp.text


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
    assert any(l.get("highlight") is True for l in data["links"])


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

    assert res_data["status"] == "approved"
    assert "ticket_id" in res_data
    assert res_data["ticket_id"].startswith("TICK-")
    assert res_data["decision_id"] == decision_id

    # 3. Verify in FalkorDB directly that status is 'approved'
    g = get_graph()
    q_check = "MATCH (d:Decision {id: $id}) RETURN d.status"
    db_res = g.query(q_check, {"id": decision_id})
    assert db_res.result_set[0][0] == "approved"

    # 4. Check /tickets endpoint to ensure ticket was recorded in tickets.jsonl
    tickets_resp = client.get("/tickets")
    assert tickets_resp.status_code == 200
    tickets_data = tickets_resp.json()
    assert tickets_data["count"] > 0
    assert any(t["decision_id"] == decision_id for t in tickets_data["tickets"])
