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
from typing import List, Dict, Any, Optional

import requests
from fastapi import FastAPI, HTTPException, Query, Request, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from dotenv import load_dotenv
load_dotenv()

from schema import get_graph
from models import TriageResponse, TriageReport
from agent import run_groq_agent_triage, run_deterministic_triage
import queries
from pdf_generator import generate_incident_pdf
from langgraph_workflow import run_langgraph_triage
from security_guardrails import run_agentic_security_audit
from logger import logger, request_id_ctx
from auth import Role, User, require_role, get_current_user
from rate_limiter import rate_limit_triage

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
TICKETS_FILE = BASE_DIR / "tickets.jsonl"

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
    Lists available vulnerability findings in the graph.
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
    for row in res.result_set:
        category = "benchmark_sleeper" if row[6] else ("benchmark_decoy" if row[7] else "osv_live")
        findings.append({
            "vuln_id": row[0],
            "cvss": float(row[1]),
            "summary": row[2],
            "fix_version": row[3],
            "package": row[4],
            "services": row[5],
            "category": category
        })
    return {"count": len(findings), "findings": findings}


@app.post("/triage", response_model=TriageResponse)
async def triage_findings(
    req: Optional[TriageRequest] = None,
    user: User = Depends(require_role(Role.ANALYST)),
    _rate_limit = Depends(rate_limit_triage)
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

    # Construct links list
    links = []
    for row in res_links.result_set:
        src, tgt, rel_type = row[0], row[1], row[2]
        if src in seen_nodes and tgt in seen_nodes:
            is_hl = (src, tgt) in highlight_edges
            links.append({
                "source": src,
                "target": tgt,
                "type": rel_type,
                "highlight": is_hl,
                "color": "#ef4444" if is_hl else "#334155"
            })

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
    _rate_limit = Depends(rate_limit_triage)
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
    print(f"Starting VulnGraph API server on http://{host}:{port}")
    uvicorn.run("main:app", host=host, port=port, reload=True)
