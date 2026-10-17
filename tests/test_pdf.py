"""
Tests for PDF Incident Report Generator (pdf_generator.py).
"""

from pdf_generator import generate_incident_pdf
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_generate_incident_pdf_bytes():
    """Verify that generate_incident_pdf returns non-empty valid PDF bytes."""
    pdf_bytes = generate_incident_pdf("CVE-2023-SLEEPER-01")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-")


def test_api_pdf_export_endpoint():
    """Verify GET /report/pdf/{vuln_id} endpoint."""
    response = client.get("/report/pdf/CVE-2023-SLEEPER-01")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert "attachment; filename=VulnGraph_Incident_CVE-2023-SLEEPER-01.pdf" in response.headers["content-disposition"]
    assert len(response.content) > 2000
    assert response.content.startswith(b"%PDF-")


def test_api_langgraph_endpoint():
    """Verify POST /triage/langgraph/{vuln_id} endpoint."""
    response = client.post("/triage/langgraph/CVE-2023-SLEEPER-01")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["lifecycle_state"] == "AWAITING_HUMAN_APPROVAL"
    assert data["risk_score"] >= 7.0
    assert "upgrade_command" in data["remediation"]
    assert "audit_hash" in data["audit"]


def test_api_guardrails_endpoint():
    """Verify GET /guardrails/{vuln_id} endpoint."""
    response = client.get("/guardrails/CVE-2023-SLEEPER-01")
    assert response.status_code == 200
    data = response.json()
    assert data["audit"]["status"] == "VERIFIED"
    assert len(data["audit"]["audit_hash"]) == 64
