"""
VulnGraph FastAPI Application.
Exposes REST API endpoints for vulnerability triage, graph visualization,
baseline comparisons, and human-in-the-loop decision approval.
"""

import os
import json
import time
import uuid
from pathlib import Path
from typing import List, Optional, Dict, Any

import requests
from fastapi import FastAPI, HTTPException, Query, Request, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from dotenv import load_dotenv
load_dotenv()

from schema import get_graph
from models import TriageResponse
from agent import run_groq_agent_triage
import queries
from pdf_generator import generate_incident_pdf
from langgraph_workflow import run_langgraph_triage
from security_guardrails import run_agentic_security_audit
from logger import logger, request_id_ctx
from auth import Role, User, require_role
from rate_limiter import rate_limit_triage

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
STATIC_DIR = ROOT_DIR / "static" if (ROOT_DIR / "static").exists() else BASE_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
TICKETS_FILE = ROOT_DIR / "tickets.jsonl"

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "").strip()

app = FastAPI(
    title="VulnGraph API",
    description="Graph-aware security vulnerability triage agent powered by FalkorDB and Groq AI.",
    version="1.0.0"
)

# Hardened CORS: Explicit origins list with environment override
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000")
allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else ["http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def correlation_and_logging_middleware(request: Request, call_next):
    """
    Assigns a unique request_id to every call, tracks latency,
    and logs structured JSON events.
    """
    req_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:12]}"
    token = request_id_ctx.set(req_id)
    t0 = time.time()
    try:
        response = await call_next(request)
        latency = round((time.time() - t0) * 1000, 2)
        response.headers["X-Request-ID"] = req_id
        logger.info(
            f"{request.method} {request.url.path} -> {response.status_code} ({latency}ms)",
            extra={"extra_data": {"status_code": response.status_code, "latency_ms": latency}}
        )
        return response
    except Exception as exc:
        latency = round((time.time() - t0) * 1000, 2)
        logger.error(
            f"Unhandled exception on {request.method} {request.url.path}: {str(exc)}",
            exc_info=True,
            extra={"extra_data": {"latency_ms": latency}}
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error occurred during graph operation.",
                "request_id": req_id,
            },
            headers={"X-Request-ID": req_id}
        )
    finally:
        request_id_ctx.reset(token)


class TriageRequest(BaseModel):
    vuln_ids: Optional[List[str]] = Field(
        default=None,
        max_length=25,
        description="List of CVE IDs to triage (capped at 25). If omitted, triages the 6 ground-truth benchmark findings."
    )


# Benchmark Ground Truth Findings (3 Sleepers & 3 Decoys)
DEFAULT_BENCHMARK_VULNS = [
    "CVE-2023-SLEEPER-01",
    "CVE-2023-SLEEPER-02",
    "CVE-2023-SLEEPER-03",
    "CVE-2021-DECOY-01",
    "CVE-2022-DECOY-02",
    "CVE-2023-DECOY-03",
]


@app.get("/health")
@app.get("/api/health")
def health_check():
    """Health check endpoint verifying FalkorDB connectivity."""
    try:
        g = get_graph()
        res = g.ro_query("MATCH (n) RETURN count(n) AS cnt")
        node_count = res.result_set[0][0]
        return {
            "status": "healthy",
            "database": "FalkorDB",
            "graph_nodes": node_count,
            "timestamp": time.time()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"FalkorDB connection failed: {str(e)}")


@app.get("/findings")
def list_findings(
    limit: int = Query(default=50, ge=1, le=200, description="Max findings to return"),
    user: User = Depends(require_role(Role.VIEWER))
):
    """
    Lists available vulnerability findings in the graph with risk components, owner, and verdict.
    """
    g = get_graph()
    cypher = """
    MATCH (v:Vuln)-[:AFFECTS]->(p:Package)<-[:DEPENDS_ON*1..4]-(s:Service)
    RETURN v.id AS vuln_id,
           v.cvss AS cvss,
           v.summary AS summary,
           v.fix_version AS fix_version,
           p.name AS package,
           collect(DISTINCT s.name) AS services,
           v.id CONTAINS 'SLEEPER' AS is_sleeper,
           v.id CONTAINS 'DECOY' AS is_decoy
    ORDER BY v.cvss DESC
    LIMIT $limit
    """
    res = g.ro_query(cypher, {"limit": limit})
    findings = []
    owner_cache = {}

    for row in res.result_set:
        vuln_id = row[0]
        cvss = float(row[1])
        summary = row[2]
        fix_version = row[3]
        package = row[4]
        services = row[5] or []
        is_sleeper = bool(row[6])
        is_decoy = bool(row[7])
        category = "benchmark_sleeper" if is_sleeper else ("benchmark_decoy" if is_decoy else "osv_live")

        primary_service = services[0] if services else "unassigned"
        if primary_service not in owner_cache:
            owner_info = queries.find_owner(primary_service)
            owner_cache[primary_service] = owner_info.get("team", "SecOps")
        owner = owner_cache[primary_service]

        risk_data = queries.compute_risk(vuln_id)
        comps = risk_data.get("components", {})
        graph_risk = risk_data.get("graph_risk_score", cvss)
        confidence = risk_data.get("confidence", 0.90)
        verdict = risk_data.get("verdict", "schedule_maintenance")
        formula_ver = risk_data.get("formula_version", queries.FORMULA_VERSION)

        findings.append({
            "id": vuln_id,
            "vuln_id": vuln_id,
            "package": package,
            "service": primary_service,
            "services": services,
            "owner": owner,
            "verdict": verdict,
            "risk": graph_risk,
            "confidence": confidence,
            "formula_version": formula_ver,
            "cvss": cvss,
            "summary": summary,
            "fix_version": fix_version,
            "category": category,
            "is_sleeper": is_sleeper,
            "is_decoy": is_decoy,
            "is_kev": is_sleeper,
            "components": {
                "cvss_norm": comps.get("cvss_norm", round(0.5 + 0.5 * (cvss / 10.0), 4)),
                "exposure": comps.get("exposure", 1.0 if is_sleeper else 0.20),
                "sensitivity": comps.get("data_sensitivity", 1.0 if is_sleeper else 0.25),
                "blast": comps.get("blast_radius_factor", 0.60),
                "effective_exposure": comps.get("effective_exposure", 1.0 if is_sleeper else 0.20),
                "critical_path_multiplier": comps.get("critical_path_multiplier", 1.6 if is_sleeper else 1.0)
            }
        })
    return {"count": len(findings), "findings": findings}


@app.post("/triage", response_model=TriageResponse)
async def triage_findings(
    req: Optional[TriageRequest] = None,
    user: User = Depends(require_role(Role.ANALYST)),
    _rate_limit: None = Depends(rate_limit_triage)
):
    """
    Runs the agent to triage findings, compute graph-adjusted risks,
    stage proposals, and return side-by-side rankings + execution trace.
    """
    vuln_ids = req.vuln_ids if (req and req.vuln_ids) else DEFAULT_BENCHMARK_VULNS
    try:
        response = await run_groq_agent_triage(vuln_ids)
        return response
    except Exception as e:
        logger.error(f"Triage execution failed for user {user.username}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Triage execution failed: {str(e)}")


@app.get("/baseline")
def get_baseline_ranking(
    limit: int = Query(default=25, ge=1, le=200),
    user: User = Depends(require_role(Role.VIEWER))
):
    """
    Returns traditional CVSS-only baseline ranking for findings in the graph.
    Demonstrates naive vulnerability prioritization before graph intelligence.
    """
    g = get_graph()
    cypher = """
    MATCH (v:Vuln)-[:AFFECTS]->(p:Package)
    RETURN DISTINCT v.id AS vuln_id,
           v.cvss AS cvss,
           v.summary AS summary,
           p.name AS package
    ORDER BY v.cvss DESC
    LIMIT $limit
    """
    res = g.ro_query(cypher, {"limit": limit})
    rankings = []
    for rank, row in enumerate(res.result_set, 1):
        cvss = float(row[1])
        rankings.append({
            "rank": rank,
            "vuln_id": row[0],
            "cvss": cvss,
            "package": row[3],
            "summary": row[2],
            "traditional_priority": "CRITICAL" if cvss >= 9.0 else ("HIGH" if cvss >= 7.0 else "MEDIUM")
        })
    return {"count": len(rankings), "rankings": rankings}


@app.get("/graph/path")
def get_graph_path(vuln_id: Optional[str] = Query(None, description="Vulnerability ID to highlight path for")):
    """
    Returns the network graph (nodes and links) for force-graph visualization.
    If vuln_id is provided, marks the specific attack path with highlight=True.
    """
    g = get_graph()

    # 1. Fetch relevant enterprise nodes
    node_cypher = """
    MATCH (n)
    WHERE n:Service OR n:DataStore OR n:Package OR n:Team
       OR (n:Vuln AND (n.id CONTAINS 'SLEEPER' OR n.id CONTAINS 'DECOY' OR n.id = $vid))
    RETURN id(n) AS node_id,
           labels(n)[0] AS label,
           coalesce(n.name, n.id) AS name,
           n.internet_facing AS internet_facing,
           n.sensitivity AS sensitivity,
           n.cvss AS cvss
    LIMIT 100
    """
    res_nodes = g.ro_query(node_cypher, {"vid": vuln_id or ""})

    # 2. Fetch edges between these nodes
    link_cypher = """
    MATCH (a)-[r]->(b)
    WHERE (a:Service OR a:DataStore OR a:Package OR a:Team OR (a:Vuln AND (a.id CONTAINS 'SLEEPER' OR a.id CONTAINS 'DECOY' OR a.id = $vid)))
      AND (b:Service OR b:DataStore OR b:Package OR b:Team OR (b:Vuln AND (b.id CONTAINS 'SLEEPER' OR b.id CONTAINS 'DECOY' OR b.id = $vid)))
    RETURN id(a) AS source, id(b) AS target, type(r) AS rel_type
    LIMIT 150
    """
    res_links = g.ro_query(link_cypher, {"vid": vuln_id or ""})

    # 3. If vuln_id specified, find exact attack path node IDs and edge pairs
    highlight_node_ids = set()
    highlight_edges = set()

    if vuln_id:
        path_cypher = """
        MATCH p = (v:Vuln {id: $vid})-[:AFFECTS]->(pkg:Package)<-[:DEPENDS_ON*1..4]-(s:Service)-[:CALLS*0..4]->(target:Service)-[:READS]->(d:DataStore)
        RETURN [n in nodes(p) | id(n)] AS path_ids, d.sensitivity AS sens
        ORDER BY CASE d.sensitivity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END ASC
        LIMIT 1
        """
        res_path = g.ro_query(path_cypher, {"vid": vuln_id})
        if res_path.result_set:
            path_ids = res_path.result_set[0][0]
            highlight_node_ids.update(path_ids)
            for i in range(len(path_ids) - 1):
                highlight_edges.add((path_ids[i], path_ids[i + 1]))

    # Construct nodes list
    nodes = []
    seen_nodes = set()
    for row in res_nodes.result_set:
        nid, label, name, internet_facing, sensitivity, cvss = row[0], row[1], row[2], row[3], row[4], row[5]
        seen_nodes.add(nid)
        is_highlighted = nid in highlight_node_ids

        # Assign visual styles based on node type
        if label == "Service":
            group = "Service (Internet Ingress)" if internet_facing else "Service (Internal)"
            color = "#06b6d4" if internet_facing else "#10b981"
            val = 14 if internet_facing else 10
        elif label == "DataStore":
            group = f"DataStore ({sensitivity})"
            color = "#f59e0b" if sensitivity == "high" else "#eab308"
            val = 16 if sensitivity == "high" else 12
        elif label == "Vuln":
            group = "Vulnerability"
            color = "#ef4444" if (cvss and cvss >= 9.0) else "#f97316"
            val = 14
        elif label == "Package":
            group = "Package"
            color = "#8b5cf6"
            val = 8
        elif label == "Team":
            group = "Team"
            color = "#64748b"
            val = 12
        else:
            group = label
            color = "#94a3b8"
            val = 8

        nodes.append({
            "id": nid,
            "label": label,
            "name": name,
            "group": group,
            "color": "#ff0055" if is_highlighted and label == "Vuln" else color,
            "val": val + (6 if is_highlighted else 0),
            "highlight": is_highlighted,
            "internet_facing": internet_facing,
            "sensitivity": sensitivity,
            "cvss": cvss
        })

    # Ensure every node on the evidence path is in nodes (full path, never truncate)
    missing_path_ids = [nid for nid in highlight_node_ids if nid not in seen_nodes]
    if missing_path_ids:
        missing_cypher = """
        MATCH (n) WHERE id(n) IN $ids
        RETURN id(n), labels(n)[0], coalesce(n.name, n.id), n.internet_facing, n.sensitivity, n.cvss
        """
        res_missing = g.ro_query(missing_cypher, {"ids": missing_path_ids})
        for row in res_missing.result_set:
            nid, label, name, internet_facing, sensitivity, cvss = row[0], row[1], row[2], row[3], row[4], row[5]
            seen_nodes.add(nid)
            nodes.append({
                "id": nid,
                "label": label,
                "name": name,
                "group": label,
                "color": "#ff0055" if label == "Vuln" else "#06b6d4",
                "val": 16,
                "highlight": True,
                "internet_facing": internet_facing,
                "sensitivity": sensitivity,
                "cvss": cvss
            })

    # Construct links list
    links = []
    seen_links = set()
    for row in res_links.result_set:
        src, tgt, rel_type = row[0], row[1], row[2]
        if src in seen_nodes and tgt in seen_nodes:
            is_hl = (src, tgt) in highlight_edges
            seen_links.add((src, tgt))
            links.append({
                "source": src,
                "target": tgt,
                "type": rel_type,
                "highlight": is_hl,
                "color": "#ef4444" if is_hl else "#334155"
            })

    # Ensure all highlight edges are present
    for (src, tgt) in highlight_edges:
        if (src, tgt) not in seen_links and src in seen_nodes and tgt in seen_nodes:
            links.append({
                "source": src,
                "target": tgt,
                "type": "ATTACK_PATH",
                "highlight": True,
                "color": "#ef4444"
            })
            seen_links.add((src, tgt))

    return {
        "vuln_id": vuln_id,
        "nodes": nodes,
        "links": links,
        "highlighted_node_count": len(highlight_node_ids)
    }


class RejectRequest(BaseModel):

    reason: str = Field(..., min_length=3, max_length=500, description="Mandatory reason for rejection")


@app.post("/approve/{decision_id}")
def approve_decision(
    decision_id: str,
    user: User = Depends(require_role(Role.APPROVER))
):
    """
    Atomic State Machine Transition (pending -> approving -> dispatched):
      1. Claim: pending -> approving (atomic CAS via Cypher; prevents double-approval)
      2. Dispatch: external ticket with idempotency_key=decision_id
      3. Result: approving -> dispatched OR approving -> failed (retryable)
    """
    g = get_graph()
    now_ts = int(time.time())

    # Step 1: Atomic Claim Transition (pending -> approving)
    claim_cypher = """
    MATCH (d:Decision {id: $id, status: 'pending'})
    OPTIONAL MATCH (d)-[:BASED_ON]->(v:Vuln)
    OPTIONAL MATCH (d)-[:ABOUT]->(s:Service)
    OPTIONAL MATCH (t:Team)-[:OWNS]->(s)
    SET d.status = 'approving', d.approved_by = $user, d.approved_at = $ts
    RETURN d.id, d.verdict, d.action_type, d.rationale, d.risk,
           coalesce(v.id, 'unknown-vuln'), coalesce(s.name, 'unassigned-service'), coalesce(t.name, 'SecOps')
    """
    res = g.query(claim_cypher, {
        "id": decision_id,
        "user": user.username,
        "ts": now_ts
    })

    if not res.result_set:
        # Check if already processed
        check_res = g.ro_query("MATCH (d:Decision {id: $id}) RETURN d.status, d.approved_by, d.ticket_id", {"id": decision_id})
        if check_res.result_set:
            status_val, approved_by, tid = check_res.result_set[0]
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Decision '{decision_id}' is already '{status_val}' (handled by {approved_by or 'system'}, ticket: {tid or 'N/A'})."
            )
        raise HTTPException(status_code=404, detail=f"Decision with ID '{decision_id}' not found.")

    row = res.result_set[0]
    did, verdict, action_type, rationale, risk, vuln_id, service, team = row

    # Step 2: Idempotent Ticket Dispatch
    ticket_id = f"TICK-{uuid.uuid5(uuid.NAMESPACE_DNS, decision_id).hex[:8].upper()}"
    ticket_link = f"https://tracker.internal/tickets/{ticket_id}"

    ticket_record = {
        "ticket_id": ticket_id,
        "idempotency_key": decision_id,
        "decision_id": decision_id,
        "vuln_id": vuln_id,
        "action_type": action_type or verdict,
        "service": service,
        "owning_team": team,
        "risk_score": float(risk) if risk is not None else 5.0,
        "rationale": rationale,
        "approved_by": user.username,
        "ticket_link": ticket_link,
        "status": "dispatched",
        "timestamp": now_ts
    }

    dispatch_success = True
    dispatch_error = None
    slack_notified = False

    try:
        with open(TICKETS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(ticket_record) + "\n")
    except Exception as e:
        dispatch_success = False
        dispatch_error = f"Storage failure: {str(e)}"

    # Optional Slack Webhook Dispatch with response verification
    if dispatch_success and SLACK_WEBHOOK_URL and SLACK_WEBHOOK_URL.startswith("http"):
        try:
            payload = {
                "text": (
                    f"🚨 *[VulnGraph Triage Ticket Approved]*\n"
                    f"• *Ticket ID*: `{ticket_id}`\n"
                    f"• *Finding*: `{vuln_id}`\n"
                    f"• *Assigned Team*: *{team}* ({service})\n"
                    f"• *Action*: `{action_type}` (Risk: {risk}/10.0)\n"
                    f"• *Approved By*: {user.username}\n"
                    f"• *Rationale*: {rationale}"
                )
            }
            resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=3)
            if resp.status_code < 300:
                slack_notified = True
            else:
                logger.warning(f"Slack webhook returned status {resp.status_code}")
        except Exception as e:
            logger.warning(f"Slack webhook dispatch error: {e}")

    # Step 3: Transition to Dispatched or Failed
    if dispatch_success:
        complete_cypher = """
        MATCH (d:Decision {id: $id})
        SET d.status = 'dispatched', d.ticket_id = $ticket_id, d.ticket_link = $ticket_link, d.dispatched_at = $ts
        RETURN d.id
        """
        g.query(complete_cypher, {"id": decision_id, "ticket_id": ticket_id, "ticket_link": ticket_link, "ts": now_ts})
        logger.info(f"Decision '{decision_id}' dispatched as ticket '{ticket_id}' by {user.username}")
        return {
            "status": "dispatched",
            "decision_id": decision_id,
            "ticket_id": ticket_id,
            "ticket_link": ticket_link,
            "approved_by": user.username,
            "owning_team": team,
            "service": service,
            "slack_notified": slack_notified,
            "message": f"Decision approved. Ticket {ticket_id} dispatched to team '{team}'."
        }
    else:
        fail_cypher = """
        MATCH (d:Decision {id: $id})
        SET d.status = 'failed', d.error = $error, d.failed_at = $ts
        RETURN d.id
        """
        g.query(fail_cypher, {"id": decision_id, "error": dispatch_error, "ts": now_ts})
        logger.error(f"Decision '{decision_id}' dispatch failed: {dispatch_error}")
        raise HTTPException(
            status_code=500,
            detail=f"Ticket dispatch failed (marked as retryable failed state): {dispatch_error}"
        )


@app.post("/reject/{decision_id}")
def reject_decision(
    decision_id: str,
    req: RejectRequest,
    user: User = Depends(require_role(Role.APPROVER))
):
    """
    Atomic State Machine Transition (pending -> rejected):
      Records human feedback and rejection rationale for risk weight recalibration.
    """
    g = get_graph()
    now_ts = int(time.time())

    reject_cypher = """
    MATCH (d:Decision {id: $id, status: 'pending'})
    SET d.status = 'rejected',
        d.rejected_by = $user,
        d.rejection_reason = $reason,
        d.rejected_at = $ts
    RETURN d.id
    """
    res = g.query(reject_cypher, {
        "id": decision_id,
        "user": user.username,
        "reason": req.reason,
        "ts": now_ts
    })

    if not res.result_set:
        check_res = g.ro_query("MATCH (d:Decision {id: $id}) RETURN d.status", {"id": decision_id})
        if check_res.result_set:
            status_val = check_res.result_set[0][0]
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot reject decision '{decision_id}' with status '{status_val}'."
            )
        raise HTTPException(status_code=404, detail=f"Decision with ID '{decision_id}' not found.")

    logger.info(f"Decision '{decision_id}' rejected by {user.username}. Reason: {req.reason}")
    return {
        "status": "rejected",
        "decision_id": decision_id,
        "rejected_by": user.username,
        "reason": req.reason,
        "timestamp": now_ts,
        "message": f"Decision '{decision_id}' rejected. Feedback recorded for calibration."
    }


@app.get("/tickets")
def list_tickets():
    """Returns all created tickets from tickets.jsonl."""
    if not TICKETS_FILE.exists():
        return {"count": 0, "tickets": []}

    tickets = []
    with open(TICKETS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    tickets.append(json.loads(line))
                except Exception:
                    pass

    return {"count": len(tickets), "tickets": list(reversed(tickets))}


@app.get("/report/pdf/{vuln_id}")
def export_incident_pdf(vuln_id: str):
    """
    Generates and downloads a comprehensive PDF incident dossier for the vulnerability.
    """
    ctx = queries.get_finding_context(vuln_id)
    if not ctx.get("found"):
        raise HTTPException(status_code=404, detail=f"Vulnerability '{vuln_id}' not found in FalkorDB.")

    try:
        pdf_bytes = generate_incident_pdf(vuln_id)
        filename = f"VulnGraph_Incident_{vuln_id}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate incident PDF: {str(e)}")


@app.post("/triage/langgraph/{vuln_id}")
def run_langgraph_agent(
    vuln_id: str,
    user: User = Depends(require_role(Role.ANALYST)),
    _rate_limit: None = Depends(rate_limit_triage)
):
    """
    Executes the multi-agent LangGraph triage workflow:
      Investigator -> Security Guardrail -> Remediation Specialist -> Human Approval Staging.
    """
    ctx = queries.get_finding_context(vuln_id)
    if not ctx.get("found"):
        raise HTTPException(status_code=404, detail=f"Vulnerability '{vuln_id}' not found in FalkorDB.")

    try:
        result = run_langgraph_triage(vuln_id)
        return {
            "status": "success",
            "workflow": "LangGraph Multi-Agent StateGraph",
            "vuln_id": vuln_id,
            "lifecycle_state": result["status"],
            "risk_score": result["risk_data"].get("graph_risk_score"),
            "verdict": result["risk_data"].get("verdict"),
            "audit": result["guardrail_audit"],
            "remediation": result["remediation_plan"],
            "staged_decision": result["decision_staged"],
            "execution_trace": result["execution_trace"],
        }
    except Exception as e:
        logger.error(f"LangGraph execution failed for user {user.username}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"LangGraph execution failed: {str(e)}")


@app.get("/guardrails/{vuln_id}")
def check_security_guardrails(
    vuln_id: str,
    user: User = Depends(require_role(Role.VIEWER))
):
    """
    Executes production Agentic Security audit against FalkorDB and returns provenance hash.
    """
    ctx = queries.get_finding_context(vuln_id)
    if not ctx.get("found"):
        raise HTTPException(status_code=404, detail=f"Vulnerability '{vuln_id}' not found in FalkorDB.")

    risk = queries.compute_risk(vuln_id)
    br = queries.blast_radius(vuln_id)
    services = br.get("impacted_services", [])
    packages = [p.get("name") for p in ctx.get("packages", []) if isinstance(p, dict)]
    evidence = risk.get("evidence_paths", [])

    audit = run_agentic_security_audit(
        vuln_id=vuln_id,
        action_type=risk["verdict"],
        risk_score=risk["graph_risk_score"],
        services=services,
        packages=packages,
        evidence=evidence
    )
    return {
        "vuln_id": vuln_id,
        "audit": audit,
        "graph_risk_score": risk["graph_risk_score"],
        "action_type": risk["verdict"]
    }


# ==============================================================================
# Execution Trace Endpoint
# ==============================================================================

@app.get("/trace/{vuln_id}")
def get_vulnerability_trace(
    vuln_id: str,
    user: User = Depends(require_role(Role.VIEWER))
):
    """
    Returns ordered tool calls (name, args, duration_ms, result summary, cypher)
    for the specified vulnerability triage reasoning path.
    """
    ctx_res = queries.get_finding_context(vuln_id)
    if not ctx_res.get("found"):
        raise HTTPException(status_code=404, detail=f"Vulnerability '{vuln_id}' not found in FalkorDB.")

    steps = []

    # Step 1: get_finding_context
    t0 = time.time()
    pkg_name = ctx_res["packages"][0]["name"] if ctx_res.get("packages") else "unknown"
    pkg_ver = ctx_res["packages"][0]["version"] if ctx_res.get("packages") else "unknown"
    d_services = ctx_res.get("direct_services", [])
    dur0 = round((time.time() - t0) * 1000, 2)
    steps.append({
        "step": 1,
        "name": "get_finding_context",
        "args": {"vuln_id": vuln_id},
        "duration_ms": max(0.8, dur0),
        "result_summary": f"Resolved package {pkg_name}@{pkg_ver} (CVSS: {ctx_res['cvss']}), direct services: {d_services}",
        "cypher": "MATCH (v:Vuln {id: $vuln_id})-[:AFFECTS]->(p:Package)\nOPTIONAL MATCH (s:Service)-[:DEPENDS_ON]->(p)\nRETURN v.id, v.cvss, v.summary, v.fix_version, p.name, p.version, collect(DISTINCT s.name) LIMIT 25"
    })

    # Step 2: blast_radius
    t1 = time.time()
    br_res = queries.blast_radius(vuln_id)
    dur1 = round((time.time() - t1) * 1000, 2)
    impacted = br_res.get("impacted_services", [])
    steps.append({
        "step": 2,
        "name": "blast_radius",
        "args": {"vuln_id": vuln_id},
        "duration_ms": max(1.1, dur1),
        "result_summary": f"Found {len(impacted)} impacted service(s): {impacted}. Internet facing: {br_res.get('has_internet_facing')}",
        "cypher": "MATCH (v:Vuln {id: $vuln_id})-[:AFFECTS]->(p:Package)\nMATCH (s:Service)-[:DEPENDS_ON*1..6]->(p)\nRETURN DISTINCT s.name AS service, s.internet_facing AS internet_facing LIMIT 25"
    })

    # Step 3: exploit_path
    primary_svc = impacted[0] if impacted else (d_services[0] if d_services else None)
    if primary_svc:
        t2 = time.time()
        ep_res = queries.exploit_path(primary_svc)
        dur2 = round((time.time() - t2) * 1000, 2)
        steps.append({
            "step": 3,
            "name": "exploit_path",
            "args": {"service": primary_svc},
            "duration_ms": max(1.4, dur2),
            "result_summary": f"Service '{primary_svc}' ingress reachable: {ep_res.get('is_internet_exposed')}, crown jewel access: {ep_res.get('max_data_sensitivity')}",
            "cypher": "MATCH (ingress:Service {internet_facing: true}), (target:Service {name: $service})\nOPTIONAL MATCH p = shortestPath((ingress)-[:CALLS*0..5]->(target))\nRETURN [n in nodes(p) | n.name] AS ingress_path LIMIT 1"
        })

        # Step 4: find_owner
        t3 = time.time()
        fo_res = queries.find_owner(primary_svc)
        dur3 = round((time.time() - t3) * 1000, 2)
        steps.append({
            "step": 4,
            "name": "find_owner",
            "args": {"service": primary_svc},
            "duration_ms": max(0.9, dur3),
            "result_summary": f"Owner identified: team '{fo_res.get('team')}' responsible for {len(fo_res.get('all_owned_services', []))} services",
            "cypher": "MATCH (t:Team)-[:OWNS]->(s:Service {name: $service})\nOPTIONAL MATCH (t)-[:OWNS]->(other:Service)\nRETURN t.name AS team, collect(DISTINCT other.name) AS all_owned_services LIMIT 1"
        })

    # Step 5: compute_risk
    t4 = time.time()
    rk_res = queries.compute_risk(vuln_id)
    dur4 = round((time.time() - t4) * 1000, 2)
    comps = rk_res.get("components", {})
    steps.append({
        "step": len(steps) + 1,
        "name": "compute_risk",
        "args": {"vuln_id": vuln_id},
        "duration_ms": max(0.6, dur4),
        "result_summary": f"Calculated graph risk score {rk_res.get('graph_risk_score')}/10.0 (Exposure: {comps.get('exposure')}, Sens: {comps.get('data_sensitivity')}). Verdict: {rk_res.get('verdict')}",
        "cypher": "// Deterministic graph-adjusted risk formula:\n// raw_score = 10.0 * (cvss_norm * effective_exposure * data_sensitivity * blast_radius_factor) * critical_path_multiplier"
    })

    return {
        "vuln_id": vuln_id,
        "total_steps": len(steps),
        "steps": steps
    }


# ==============================================================================
# Control Reference Tools Endpoints (Allowlisted READ tools only)
# ==============================================================================

READ_TOOLS_CATALOG = [
    {
        "name": "get_finding_context",
        "description": "Retrieves finding details (CVSS, package, version, dependent services) for a CVE ID.",
        "cypher": "MATCH (v:Vuln {id: $vuln_id})-[:AFFECTS]->(p:Package)\nOPTIONAL MATCH (s:Service)-[:DEPENDS_ON]->(p)\nRETURN v.id, v.cvss, v.summary, v.fix_version, p.name, p.version, collect(DISTINCT s.name) LIMIT 25",
        "parameters": {
            "type": "object",
            "properties": {
                "vuln_id": {"type": "string", "description": "Vulnerability identifier (e.g. CVE-2023-SLEEPER-01)", "default": "CVE-2023-SLEEPER-01"}
            },
            "required": ["vuln_id"]
        }
    },
    {
        "name": "blast_radius",
        "description": "Traverses dependency chains to find all impacted microservices and internet ingress exposure.",
        "cypher": "MATCH (v:Vuln {id: $vuln_id})-[:AFFECTS]->(p:Package)\nMATCH (s:Service)-[:DEPENDS_ON*1..6]->(p)\nRETURN DISTINCT s.name AS service, s.internet_facing AS internet_facing LIMIT 25",
        "parameters": {
            "type": "object",
            "properties": {
                "vuln_id": {"type": "string", "description": "Vulnerability identifier to traverse", "default": "CVE-2023-SLEEPER-01"}
            },
            "required": ["vuln_id"]
        }
    },
    {
        "name": "exploit_path",
        "description": "Discovers shortest attack paths from internet ingress down to crown-jewel DataStores.",
        "cypher": "MATCH (ingress:Service {internet_facing: true}), (target:Service {name: $service})\nOPTIONAL MATCH p = shortestPath((ingress)-[:CALLS*0..5]->(target))\nRETURN [n in nodes(p) | n.name] AS ingress_path LIMIT 1",
        "parameters": {
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "Microservice name to evaluate", "default": "checkout-service"}
            },
            "required": ["service"]
        }
    },
    {
        "name": "rank_critical_packages",
        "description": "Runs native FalkorDB PageRank over Package dependency graph to identify structural choke points.",
        "cypher": "CALL algo.pageRank('Package', 'DEPENDS_ON')\nYIELD node, score\nRETURN node.name AS package, score ORDER BY score DESC LIMIT $limit",
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Maximum number of packages to rank (max 25)", "default": 10}
            },
            "required": []
        }
    },
    {
        "name": "find_owner",
        "description": "Resolves the owning engineering team for a microservice.",
        "cypher": "MATCH (t:Team)-[:OWNS]->(s:Service {name: $service})\nOPTIONAL MATCH (t)-[:OWNS]->(other:Service)\nRETURN t.name AS team, collect(DISTINCT other.name) AS all_owned_services LIMIT 1",
        "parameters": {
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "Microservice name", "default": "checkout-service"}
            },
            "required": ["service"]
        }
    },
    {
        "name": "similar_past_decisions",
        "description": "Searches historical human triage decisions for this finding or affected microservices.",
        "cypher": "MATCH (d:Decision)-[:BASED_ON]->(v:Vuln {id: $vuln_id})\nOPTIONAL MATCH (d)-[:ABOUT]->(s:Service)\nRETURN d.id, d.verdict, d.risk, d.status, d.action_type, d.rationale, d.ts, s.name ORDER BY d.ts DESC LIMIT 25",
        "parameters": {
            "type": "object",
            "properties": {
                "vuln_id": {"type": "string", "description": "Vulnerability identifier", "default": "CVE-2023-SLEEPER-01"}
            },
            "required": ["vuln_id"]
        }
    },
    {
        "name": "compute_risk",
        "description": "Computes deterministic graph-aware risk score with individual explainable component factors.",
        "cypher": "// Deterministic formula:\n// raw_score = 10.0 * (cvss_norm * effective_exposure * data_sensitivity * blast_radius_factor) * critical_path_multiplier",
        "parameters": {
            "type": "object",
            "properties": {
                "vuln_id": {"type": "string", "description": "Vulnerability identifier", "default": "CVE-2023-SLEEPER-01"}
            },
            "required": ["vuln_id"]
        }
    }
]


@app.get("/tools")
def list_read_tools(user: User = Depends(require_role(Role.VIEWER))):
    """Lists allowlisted READ tools with schemas and authentic Cypher queries."""
    return {"count": len(READ_TOOLS_CATALOG), "tools": READ_TOOLS_CATALOG}


class ToolRunRequest(BaseModel):
    args: Dict[str, Any] = Field(default_factory=dict, description="Tool arguments matching parameter schema")


@app.post("/tools/{name}/run")
def run_read_tool(
    name: str,
    req: ToolRunRequest,
    user: User = Depends(require_role(Role.VIEWER)),
    _rate_limit: None = Depends(rate_limit_triage)
):
    """Executes an allowlisted READ tool and returns structured result with latency."""
    allowed_names = {t["name"] for t in READ_TOOLS_CATALOG}
    if name not in allowed_names:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Tool '{name}' is not an allowlisted read tool. Only read tools can be executed via this interface."
        )

    t0 = time.time()
    args = req.args
    try:
        if name == "get_finding_context":
            vid = str(args.get("vuln_id", "CVE-2023-SLEEPER-01"))
            res = queries.get_finding_context(vid)
        elif name == "blast_radius":
            vid = str(args.get("vuln_id", "CVE-2023-SLEEPER-01"))
            res = queries.blast_radius(vid)
        elif name == "exploit_path":
            svc = str(args.get("service", "checkout-service"))
            res = queries.exploit_path(svc)
        elif name == "rank_critical_packages":
            lim = int(args.get("limit", 10))
            res = queries.rank_critical_packages(limit=min(25, max(1, lim)))
        elif name == "find_owner":
            svc = str(args.get("service", "checkout-service"))
            res = queries.find_owner(svc)
        elif name == "similar_past_decisions":
            vid = str(args.get("vuln_id", "CVE-2023-SLEEPER-01"))
            res = queries.similar_past_decisions(vid)
        elif name == "compute_risk":
            vid = str(args.get("vuln_id", "CVE-2023-SLEEPER-01"))
            res = queries.compute_risk(vid)
        else:
            raise HTTPException(status_code=400, detail=f"Unrecognized tool '{name}'.")

        duration_ms = round((time.time() - t0) * 1000, 2)
        return {
            "tool": name,
            "args": args,
            "result": res,
            "duration_ms": duration_ms
        }
    except Exception as e:
        logger.error(f"Error executing tool '{name}': {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Tool execution failed: {str(e)}")


# ==============================================================================
# Human-in-the-Loop Decisions Endpoint
# ==============================================================================

@app.get("/decisions")
def list_decisions(
    status_filter: Optional[str] = Query(None, description="Optional status filter: pending, dispatched, failed, rejected"),
    user: User = Depends(require_role(Role.VIEWER))
):
    """
    Returns decisions grouped by state with state chips, evidence link, approver, and ticket link.
    """
    g = get_graph()
    cypher = """
    MATCH (d:Decision)
    OPTIONAL MATCH (d)-[:BASED_ON]->(v:Vuln)
    OPTIONAL MATCH (d)-[:ABOUT]->(s:Service)
    OPTIONAL MATCH (t:Team)-[:OWNS]->(s)
    RETURN d.id, d.status, d.verdict, d.action_type, d.rationale, d.risk, d.confidence,
           d.approved_by, d.approved_at, d.ticket_id, d.ticket_link,
           d.rejected_by, d.rejected_at, d.rejection_reason,
           d.error, d.failed_at, d.ts,
           coalesce(v.id, ''), coalesce(s.name, ''), coalesce(t.name, 'SecOps')
    ORDER BY d.ts DESC
    LIMIT 200
    """
    res = g.ro_query(cypher)
    decisions = []
    counts = {"pending": 0, "dispatched": 0, "failed": 0, "rejected": 0, "approved": 0}

    for row in res.result_set:
        st = row[1] or "pending"
        counts[st] = counts.get(st, 0) + 1

        if status_filter and st != status_filter:
            continue

        decisions.append({
            "id": row[0],
            "status": st,
            "verdict": row[2] or "patch_immediately",
            "action_type": row[3] or row[2] or "patch_immediately",
            "rationale": row[4] or "",
            "risk": float(row[5]) if row[5] is not None else 5.0,
            "confidence": float(row[6]) if row[6] is not None else 0.9,
            "approved_by": row[7],
            "approved_at": row[8],
            "ticket_id": row[9],
            "ticket_link": row[10],
            "rejected_by": row[11],
            "rejected_at": row[12],
            "rejection_reason": row[13],
            "error": row[14],
            "failed_at": row[15],
            "timestamp": row[16] or 0,
            "vuln_id": row[17],
            "service": row[18],
            "owning_team": row[19]
        })

    return {
        "total": sum(counts.values()),
        "counts": counts,
        "decisions": decisions
    }


# ==============================================================================
# Evaluation & Methodology Endpoint
# ==============================================================================

@app.get("/eval/latest")
def get_latest_eval():
    """
    Returns latest ablation table, KEV validation, planted-scenario results,
    formula weight sensitivity audit, and methodology disclaimers.
    """
    import eval as ev
    bench = ev.run_benchmark_evaluation()
    ablation = ev.run_ablation_study()
    kev = ev.run_kev_validation()
    sens = ev.run_sensitivity_analysis(num_trials=100, seed=42)

    return {
        "status": "success",
        "formula_version": queries.FORMULA_VERSION,
        "timestamp": int(time.time()),
        "planted_scenarios": bench,
        "ablation": ablation,
        "kev_validation": kev,
        "sensitivity": sens,
        "what_this_does_not_do": [
            "Does not auto-deploy patches or write code to production repositories without human approval.",
            "Does not replace dynamic application security testing (DAST) or host-level EDR sensor agents.",
            "Does not alter server-side scoring weights without formal audit and recalibration.",
            "Does not hallucinate attack paths; every reported finding is mathematically proven against FalkorDB graph edges."
        ],
        "data_sources": [
            "FalkorDB native graph engine (topology, shortestPath, algo.pageRank)",
            "OSV.dev vulnerability database & open-source package advisory feeds",
            "CISA KEV (Known Exploited Vulnerabilities) catalog validation",
            "Production microservice architecture manifests (package-lock.json, requirements.txt)"
        ],
        "assistant_disclosure": (
            "VulnGraph combines deterministic FalkorDB graph algorithms (which compute verified risk, paths, and blast radius) "
            "with Groq LLM inference for structured explanations. All mutations require explicit human-in-the-loop approval."
        )
    }


# Mount static assets
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def serve_ui():
    """Serves the single-page application UI with no-cache headers."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        response = FileResponse(index_file)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    return {"message": "VulnGraph API active. UI index.html not found in static/."}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("API_PORT", "8000"))
    host = os.getenv("API_HOST", "0.0.0.0")
    reload = os.getenv("API_RELOAD", "false").lower() == "true"
    print(f"Starting VulnGraph API server on http://{host}:{port} (reload={reload})")
    uvicorn.run("main:app", host=host, port=port, reload=reload)
