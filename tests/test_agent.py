"""
Test suite for VulnGraph Agent Loop, Verdict Validation, and Trace Logging.
"""

import pytest
import asyncio
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from models import FindingVerdict, TriageReport, TraceStep, TriageResponse
from agent import (
    load_system_prompt,
    clean_json_text,
    run_deterministic_triage,
    run_groq_agent_triage,
    run_mistral_agent_triage
)


def test_load_system_prompt():
    prompt = load_system_prompt()
    assert "VulnGraph" in prompt
    assert "FINAL ANSWER OUTPUT SCHEMA" in prompt
    assert "patch_immediately" in prompt
    assert "propose_action" in prompt


def test_clean_json_text():
    raw_md = "```json\n{\"test\": 123}\n```"
    cleaned = clean_json_text(raw_md)
    assert cleaned == "{\"test\": 123}"

    raw_plain = "  {\"key\": \"val\"}  "
    assert clean_json_text(raw_plain) == "{\"key\": \"val\"}"


def test_deterministic_agent_triage():
    async def _test():
        vuln_ids = ["CVE-2023-SLEEPER-01", "CVE-2021-DECOY-01"]
        response = await run_deterministic_triage(vuln_ids)

        assert isinstance(response, TriageResponse)
        assert len(response.report.findings) == 2
        assert len(response.trace) > 0

        # Verify trace structure
        tool_calls = [t for t in response.trace if t.call_type == "tool_call"]
        assert len(tool_calls) >= 4
        assert any(t.tool_name == "compute_risk" for t in tool_calls)
        assert any(t.tool_name == "blast_radius" for t in tool_calls)

        # Verify findings
        findings_map = {f.vuln_id: f for f in response.report.findings}
        sleeper = findings_map["CVE-2023-SLEEPER-01"]
        decoy = findings_map["CVE-2021-DECOY-01"]

        assert sleeper.verdict == "patch_immediately"
        assert sleeper.has_internet_exposure is True
        assert sleeper.max_data_sensitivity == "high"
        assert sleeper.decision_id is not None
        assert sleeper.decision_id.startswith("dec-")

        assert decoy.verdict == "deprioritize"
        assert decoy.has_internet_exposure is False
        assert decoy.max_data_sensitivity == "low"

        # Verify Graph-aware vs Baseline reordering
        # Sleeper graph risk > Decoy graph risk
        assert sleeper.graph_risk_score > decoy.graph_risk_score
        # But Decoy CVSS > Sleeper CVSS
        assert decoy.cvss_raw > sleeper.cvss_raw

        # Baseline ranking ranks Decoy first
        assert response.baseline_ranking[0]["vuln_id"] == "CVE-2021-DECOY-01"
        # Graph ranking ranks Sleeper first
        assert response.graph_ranking[0]["vuln_id"] == "CVE-2023-SLEEPER-01"

    asyncio.run(_test())


def test_pydantic_schema_strictness():
    # Valid verdict
    v = FindingVerdict(
        vuln_id="CVE-2023-SLEEPER-01",
        cvss_raw=5.3,
        graph_risk_score=7.34,
        verdict="patch_immediately",
        impacted_services=["checkout-service"],
        owning_teams=["checkout-squad"],
        has_internet_exposure=True,
        max_data_sensitivity="high",
        evidence_paths=["checkout -> vault"],
        decision_id="dec-1234",
        rationale="Critical internet path to payment data"
    )
    assert v.verdict == "patch_immediately"

    # Invalid verdict value should raise ValidationError
    with pytest.raises(Exception):
        FindingVerdict(
            vuln_id="CVE-2023-SLEEPER-01",
            cvss_raw=5.3,
            graph_risk_score=7.34,
            verdict="invalid_verdict_value",  # Not in Literal
            impacted_services=["checkout-service"],
            owning_teams=["checkout-squad"],
            has_internet_exposure=True,
            max_data_sensitivity="high",
            rationale="Test"
        )


def test_run_agent_triage_wrapper():
    async def _test():
        # Tests the top-level agent triage wrapper with all 6 ground truth findings
        ground_truth = [
            "CVE-2023-SLEEPER-01",
            "CVE-2023-SLEEPER-02",
            "CVE-2023-SLEEPER-03",
            "CVE-2021-DECOY-01",
            "CVE-2022-DECOY-02",
            "CVE-2023-DECOY-03",
        ]
        res = await run_groq_agent_triage(ground_truth)

        assert len(res.report.findings) == 6
        assert res.steps_taken > 0
        assert res.latency_ms > 0

        # Check that top 3 in graph ranking are ALL Sleepers
        top_3_graph = [item["vuln_id"] for item in res.graph_ranking[:3]]
        assert all("SLEEPER" in vid for vid in top_3_graph)

        # Check that top 3 in baseline CVSS ranking are ALL Decoys
        top_3_baseline = [item["vuln_id"] for item in res.baseline_ranking[:3]]
        assert all("DECOY" in vid for vid in top_3_baseline)

    asyncio.run(_test())
