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
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from dotenv import load_dotenv
load_dotenv()

from schema import get_graph
from models import TriageResponse, TriageReport
from agent import run_groq_agent_triage, run_deterministic_triage
import queries

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

# CORS middleware for frontend flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TriageRequest(BaseModel):
    vuln_ids: Optional[List[str]] = Field(
        default=None,
        description="List of CVE IDs to triage. If omitted, triages the 6 ground-truth benchmark findings."
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
def list_findings(limit: int = 50):
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
async def triage_findings(req: Optional[TriageRequest] = None):
    """
    Runs the agent to triage findings, compute graph-adjusted risks,
    stage proposals, and return side-by-side rankings + execution trace.
    """
    vuln_ids = req.vuln_ids if (req and req.vuln_ids) else DEFAULT_BENCHMARK_VULNS
    try:
        response = await run_groq_agent_triage(vuln_ids)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Triage execution failed: {str(e)}")


@app.get("/baseline")
def get_baseline_ranking(limit: int = 25):
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


@app.post("/approve/{decision_id}")
def approve_decision(decision_id: str):
    """
    HUMAN-IN-THE-LOOP APPROVAL ENDPOINT:
    Approves a staged Decision node in FalkorDB, writes the verified action ticket
    to tickets.jsonl, and optionally notifies Slack.
    """
    g = get_graph()

    # 1. Fetch decision and connected context
    fetch_cypher = """
    MATCH (d:Decision {id: $id})
    OPTIONAL MATCH (d)-[:BASED_ON]->(v:Vuln)
    OPTIONAL MATCH (d)-[:ABOUT]->(s:Service)
    OPTIONAL MATCH (t:Team)-[:OWNS]->(s)
    RETURN d.id AS decision_id,
           d.status AS status,
           d.verdict AS verdict,
           d.action_type AS action_type,
           d.rationale AS rationale,
           d.risk AS risk,
           coalesce(v.id, 'unknown-vuln') AS vuln_id,
           coalesce(s.name, 'unassigned-service') AS service,
           coalesce(t.name, 'security-squad') AS team
    """
    res = g.query(fetch_cypher, {"id": decision_id})
    if not res.result_set:
        raise HTTPException(status_code=404, detail=f"Decision with ID '{decision_id}' not found.")

    row = res.result_set[0]
    curr_status = row[1]
    if curr_status == "approved":
        return {
            "status": "already_approved",
            "decision_id": decision_id,
            "message": f"Decision '{decision_id}' was already approved."
        }

    verdict, action_type, rationale, risk, vuln_id, service, team = (
        row[2], row[3], row[4], row[5], row[6], row[7], row[8]
    )

    # 2. Update status in FalkorDB
    now_ts = int(time.time())
    update_cypher = """
    MATCH (d:Decision {id: $id})
    SET d.status = 'approved', d.approved_at = $ts
    RETURN d.id, d.status
    """
    g.query(update_cypher, {"id": decision_id, "ts": now_ts})

    # 3. Create ticket record in tickets.jsonl
    ticket_id = f"TICK-{uuid.uuid4().hex[:6].upper()}"
    ticket_record = {
        "ticket_id": ticket_id,
        "decision_id": decision_id,
        "vuln_id": vuln_id,
        "action_type": action_type or verdict,
        "service": service,
        "owning_team": team,
        "risk_score": float(risk) if risk is not None else 5.0,
        "rationale": rationale,
        "status": "created",
        "approved_at": now_ts
    }

    try:
        with open(TICKETS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(ticket_record) + "\n")
    except Exception as e:
        print(f"[Tickets] Error saving to tickets.jsonl: {e}")

    # 4. Optional Slack webhook dispatch
    slack_notified = False
    if SLACK_WEBHOOK_URL and SLACK_WEBHOOK_URL.startswith("http"):
        try:
            payload = {
                "text": (
                    f"🚨 *[VulnGraph Triage Ticket Approved]*\n"
                    f"• *Ticket ID*: `{ticket_id}`\n"
                    f"• *Finding*: `{vuln_id}`\n"
                    f"• *Assigned Team*: *{team}* ({service})\n"
                    f"• *Action*: `{action_type}` (Risk: {risk}/10.0)\n"
                    f"• *Rationale*: {rationale}"
                )
            }
            requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=3)
            slack_notified = True
        except Exception as e:
            print(f"[Slack Webhook] Failed to dispatch: {e}")

    return {
        "status": "approved",
        "ticket_id": ticket_id,
        "decision_id": decision_id,
        "vuln_id": vuln_id,
        "service": service,
        "owning_team": team,
        "slack_notified": slack_notified,
        "message": f"Decision approved. Ticket {ticket_id} dispatched to team '{team}'."
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


# Mount static assets
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def serve_ui():
    """Serves the single-page application UI."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "VulnGraph API active. UI index.html not found in static/."}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("API_PORT", "8000"))
    host = os.getenv("API_HOST", "0.0.0.0")
    print(f"Starting VulnGraph API server on http://{host}:{port}")
    uvicorn.run("main:app", host=host, port=port, reload=True)
