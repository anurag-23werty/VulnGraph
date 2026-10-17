"""
Pydantic schemas for VulnGraph verdicts, triage reports, and execution traces.
"""

from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field


class FindingVerdict(BaseModel):
    """
    Individual vulnerability verdict validated with graph-grounded evidence.
    """
    vuln_id: str = Field(..., description="Vulnerability CVE identifier")
    cvss_raw: float = Field(..., description="Raw CVSS base score (0.0 - 10.0)")
    graph_risk_score: float = Field(..., description="Graph-adjusted risk score (0.0 - 10.0)")
    verdict: Literal["patch_immediately", "schedule_maintenance", "deprioritize"] = Field(
        ..., description="Actionable triage verdict"
    )
    impacted_services: List[str] = Field(default_factory=list, description="Services affected directly or transitively")
    owning_teams: List[str] = Field(default_factory=list, description="Engineering squads responsible for affected services")
    has_internet_exposure: bool = Field(..., description="Whether finding is reachable from internet ingress")
    max_data_sensitivity: Literal["high", "medium", "low", "none"] = Field(
        ..., description="Highest sensitivity data store reachable"
    )
    evidence_paths: List[str] = Field(default_factory=list, description="Graph traversal evidence chains")
    decision_id: Optional[str] = Field(None, description="Staged Decision ID in FalkorDB if action was proposed")
    rationale: str = Field(..., description="Technical explanation grounded in graph relationships")


class TriageReport(BaseModel):
    """
    Complete triage report returned by the agent.
    """
    summary: str = Field(..., description="Executive summary of the triage run")
    findings: List[FindingVerdict] = Field(..., description="List of ranked finding verdicts")


class TraceStep(BaseModel):
    """
    Log of a single action in the agent's multi-step decision loop.
    """
    step: int
    call_type: Literal["llm_call", "tool_call", "verdict", "error", "retry"]
    tool_name: Optional[str] = None
    arguments: Optional[Dict[str, Any]] = None
    result: Optional[Any] = None
    timestamp: float


class TriageResponse(BaseModel):
    """
    API response model containing the structured report, trace logs, and baseline comparison.
    """
    report: TriageReport
    trace: List[TraceStep]
    steps_taken: int
    latency_ms: float
    baseline_ranking: List[Dict[str, Any]]
    graph_ranking: List[Dict[str, Any]]
