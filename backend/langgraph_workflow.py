"""
LangGraph Multi-Agent Security Triage Workflow.
==============================================
Orchestrates autonomous agents acting on FalkorDB connected data using LangGraph:
  1. Investigator Node: Gathers graph topology, blast radius, exploit paths, and risk scores.
  2. Security Guardrail Node: Production Agentic Security audit (hallucination defense & policy check).
  3. Remediation Specialist Node: Generates exact upgrade commands and compensating controls.
  4. Human-in-the-Loop Node: Stages pending action in FalkorDB for human analyst review.
"""

from typing import TypedDict, List, Dict, Any, Optional
from datetime import datetime, timezone
from langgraph.graph import StateGraph, START, END

from queries import (
    get_finding_context,
    blast_radius,
    exploit_path,
    compute_risk,
    find_owner,
    propose_action
)
from security_guardrails import run_agentic_security_audit
from remediation import generate_remediation_plan


class VulnTriageState(TypedDict):
    vuln_id: str
    finding_context: Dict[str, Any]
    blast_radius_info: Dict[str, Any]
    exploit_path_info: Dict[str, Any]
    owner_info: Dict[str, Any]
    risk_data: Dict[str, Any]
    guardrail_audit: Dict[str, Any]
    remediation_plan: Dict[str, Any]
    decision_staged: Dict[str, Any]
    execution_trace: List[Dict[str, Any]]
    status: str
    error: Optional[str]


def investigate_node(state: VulnTriageState) -> Dict[str, Any]:
    """
    Investigator Agent:
    Traverses FalkorDB graph to discover blast radius, attack ingress, and risk score.
    """
    vid = state["vuln_id"]
    trace = list(state.get("execution_trace", []))
    t0 = datetime.now(timezone.utc).isoformat()
    ctx = get_finding_context(vid)
    packages = [p.get("name") for p in ctx.get("packages", []) if isinstance(p, dict)]
    trace.append({"step": "investigate_finding_context", "timestamp": t0, "result": f"Found {len(packages)} packages: {', '.join(packages)}"})

    br = blast_radius(vid)
    trace.append({"step": "investigate_blast_radius", "timestamp": t0, "result": f"Discovered {len(br.get('impacted_services', []))} impacted services"})

    # Evaluate exploit path for the primary service
    services = br.get("impacted_services", [])
    primary_svc = services[0] if services else "api-gateway"
    ep = exploit_path(primary_svc)
    trace.append({"step": "investigate_exploit_path", "timestamp": t0, "result": f"Ingress exposed: {ep.get('is_internet_exposed', False)}"})

    owner = find_owner(primary_svc)
    risk = compute_risk(vid)
    trace.append({"step": "compute_graph_risk", "timestamp": t0, "result": f"Calculated Graph Risk: {risk['graph_risk_score']}"})

    return {
        "finding_context": ctx,
        "blast_radius_info": br,
        "exploit_path_info": ep,
        "owner_info": owner,
        "risk_data": risk,
        "execution_trace": trace,
        "status": "INVESTIGATED"
    }


def security_guardrail_node(state: VulnTriageState) -> Dict[str, Any]:
    """
    Security Auditor Agent (Agentic Security for Production):
    Validates agent findings against FalkorDB to prevent hallucinations and policy breaches.
    """
    vid = state["vuln_id"]
    risk = state["risk_data"]
    ctx = state["finding_context"]
    br = state["blast_radius_info"]
    trace = list(state["execution_trace"])

    action_type = risk.get("verdict", "schedule_maintenance")
    services = br.get("impacted_services", [])
    packages = [p.get("name") for p in ctx.get("packages", []) if isinstance(p, dict)]
    evidence = risk.get("evidence_paths", [f"Vulnerability {vid} affects {services}"])

    audit = run_agentic_security_audit(
        vuln_id=vid,
        action_type=action_type,
        risk_score=risk.get("graph_risk_score", 0.0),
        services=services,
        packages=packages,
        evidence=evidence
    )

    trace.append({
        "step": "agentic_security_audit",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result": f"Audit {audit['status']} (SHA-256: {audit['audit_hash'][:10]}...)"
    })

    return {
        "guardrail_audit": audit,
        "execution_trace": trace,
        "status": "AUDITED" if audit["all_passed"] else "AUDIT_FLAGGED"
    }


def remediation_node(state: VulnTriageState) -> Dict[str, Any]:
    """
    Remediation Specialist Agent:
    Builds concrete upgrade commands, compensating controls, and containment strategies.
    """
    vid = state["vuln_id"]
    ctx = state["finding_context"]
    risk = state["risk_data"]
    br = state["blast_radius_info"]
    ep = state["exploit_path_info"]
    trace = list(state["execution_trace"])

    packages_info = ctx.get("packages", [])
    if packages_info and isinstance(packages_info[0], dict):
        pkg_name = packages_info[0].get("name", "unknown-package")
        pkg_ver = packages_info[0].get("version", "1.0.0")
    else:
        pkg_name = "unknown-package"
        pkg_ver = "1.0.0"

    fix_ver = ctx.get("fix_version") or "latest-patched"
    is_exposed = ep.get("is_internet_exposed", False)
    impacted = br.get("impacted_services", [])

    plan = generate_remediation_plan(
        vuln_id=vid,
        package_name=pkg_name,
        package_version=pkg_ver,
        fix_version=fix_ver,
        is_internet_exposed=is_exposed,
        impacted_services=impacted,
        risk_score=risk.get("graph_risk_score", 0.0)
    )

    trace.append({
        "step": "remediation_planning",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result": f"Generated CLI upgrade command for {plan['ecosystem']}: {plan['upgrade_command']}"
    })

    return {
        "remediation_plan": plan,
        "execution_trace": trace,
        "status": "REMEDIATION_PLANNED"
    }


def human_in_the_loop_stage_node(state: VulnTriageState) -> Dict[str, Any]:
    """
    Human-in-the-Loop Node:
    Stages proposed action in FalkorDB with status strictly set to 'pending'.
    Mutating tickets are never dispatched without human analyst approval.
    """
    vid = state["vuln_id"]
    risk = state["risk_data"]
    audit = state["guardrail_audit"]
    trace = list(state["execution_trace"])

    action_type = risk.get("verdict", "schedule_maintenance")
    evidence = risk.get("evidence_paths", [])

    rationale = (
        f"LangGraph Agentic Assessment: Graph Risk {risk.get('graph_risk_score', 0.0)}/10.0. "
        f"Audit status: {audit.get('status', 'VERIFIED')}. "
        f"Ingress exposed: {risk.get('has_internet_exposure', False)}. "
        f"Action: {action_type}."
    )

    # Propose staged decision in FalkorDB
    staged = propose_action(
        vuln_id=vid,
        action_type=action_type,
        rationale=rationale,
        evidence=evidence
    )

    trace.append({
        "step": "human_in_the_loop_staged",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result": f"Decision node staged in FalkorDB with id '{staged.get('decision_id')}' (status: pending)"
    })

    return {
        "decision_staged": staged,
        "execution_trace": trace,
        "status": "AWAITING_HUMAN_APPROVAL"
    }


def create_vuln_triage_graph():
    """
    Compiles the LangGraph StateGraph.
    """
    builder = StateGraph(VulnTriageState)

    # Add agent nodes
    builder.add_node("investigate", investigate_node)
    builder.add_node("security_guardrail", security_guardrail_node)
    builder.add_node("remediation", remediation_node)
    builder.add_node("human_in_the_loop_stage", human_in_the_loop_stage_node)

    # Connect workflow edges
    builder.add_edge(START, "investigate")
    builder.add_edge("investigate", "security_guardrail")
    builder.add_edge("security_guardrail", "remediation")
    builder.add_edge("remediation", "human_in_the_loop_stage")
    builder.add_edge("human_in_the_loop_stage", END)

    return builder.compile()


# Compiled singleton graph
_triage_graph = None


def get_triage_graph():
    global _triage_graph
    if _triage_graph is None:
        _triage_graph = create_vuln_triage_graph()
    return _triage_graph


def run_langgraph_triage(vuln_id: str) -> Dict[str, Any]:
    """
    Executes the multi-agent LangGraph workflow for a given vulnerability.
    """
    graph = get_triage_graph()
    initial_state: VulnTriageState = {
        "vuln_id": vuln_id,
        "finding_context": {},
        "blast_radius_info": {},
        "exploit_path_info": {},
        "owner_info": {},
        "risk_data": {},
        "guardrail_audit": {},
        "remediation_plan": {},
        "decision_staged": {},
        "execution_trace": [],
        "status": "INITIALIZED",
        "error": None
    }

    final_state = graph.invoke(initial_state)
    return dict(final_state)
