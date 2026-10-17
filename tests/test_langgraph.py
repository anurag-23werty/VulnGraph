"""
Tests for LangGraph Multi-Agent Workflow (langgraph_workflow.py).
"""

from langgraph_workflow import run_langgraph_triage, create_vuln_triage_graph


def test_create_vuln_triage_graph_compilation():
    """Verify that the LangGraph StateGraph compiles without errors."""
    graph = create_vuln_triage_graph()
    assert graph is not None


def test_run_langgraph_triage_execution():
    """
    Verify complete multi-agent workflow:
      investigate -> security_guardrail -> remediation -> human_in_the_loop_stage
    """
    res = run_langgraph_triage("CVE-2023-SLEEPER-01")
    assert res is not None
    assert res["vuln_id"] == "CVE-2023-SLEEPER-01"
    assert res["status"] == "AWAITING_HUMAN_APPROVAL"

    # Risk data
    assert res["risk_data"]["graph_risk_score"] >= 7.0
    assert res["risk_data"]["verdict"] == "patch_immediately"

    # Agentic security audit
    assert res["guardrail_audit"]["status"] == "VERIFIED"
    assert len(res["guardrail_audit"]["audit_hash"]) == 64

    # Remediation playbook
    assert "upgrade_command" in res["remediation_plan"]
    assert "urllib3" in res["remediation_plan"]["upgrade_command"]

    # Staged decision in FalkorDB
    assert "decision_id" in res["decision_staged"]
    assert res["decision_staged"]["decision_id"].startswith("dec-")

    # Execution trace has all agent steps
    steps = [t["step"] for t in res["execution_trace"]]
    assert "investigate_finding_context" in steps
    assert "investigate_blast_radius" in steps
    assert "agentic_security_audit" in steps
    assert "remediation_planning" in steps
    assert "human_in_the_loop_staged" in steps
