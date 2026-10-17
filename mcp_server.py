"""
VulnGraph Model Context Protocol (MCP) Server.
Built with FastMCP to expose FalkorDB Cypher traversals and graph algorithms as typed MCP tools.

Provides 7 READ tools (using ro_query) and 1 STAGED WRITE tool (propose_action).
Results are compact JSON capped at 25 rows.
"""

import json
from typing import List, Dict, Any, Optional
from fastmcp import FastMCP

import queries

# Initialize FastMCP Server
mcp = FastMCP(
    name="vulngraph-mcp"
)


@mcp.tool()
def get_finding_context(vuln_id: str) -> str:
    """
    Retrieves full finding details for a vulnerability ID:
    CVSS base score, summary description, recommended fix version,
    the affected package name/version, and directly dependent services.
    
    Args:
        vuln_id: The CVE or vulnerability identifier (e.g. 'CVE-2023-SLEEPER-01').
    """
    res = queries.get_finding_context(vuln_id=vuln_id)
    return json.dumps(res, indent=2)


@mcp.tool()
def blast_radius(vuln_id: str) -> str:
    """
    Traverses multi-hop dependency chains (DEPENDS_ON*1..6) from Services down to
    the vulnerable package. Returns all impacted services, dependency chains,
    and flags whether any impacted service is exposed to the internet.
    
    Args:
        vuln_id: The CVE identifier to evaluate.
    """
    res = queries.blast_radius(vuln_id=vuln_id)
    return json.dumps(res, indent=2)


@mcp.tool()
def exploit_path(service: str) -> str:
    """
    Finds shortest attack paths using FalkorDB's shortestPath algorithm:
    1. Checks if an internet-facing ingress service can reach this service via CALLS*0..5.
    2. Checks if this service can reach high- or medium-sensitivity DataStores via READS.
    
    Args:
        service: Name of the microservice to analyze (e.g. 'checkout-service').
    """
    res = queries.exploit_path(service=service)
    return json.dumps(res, indent=2)


@mcp.tool()
def rank_critical_packages(limit: int = 25) -> str:
    """
    Runs FalkorDB's native PageRank algorithm over Package nodes connected by
    DEPENDS_ON relationships to find structurally central, high-impact packages.
    
    Args:
        limit: Maximum number of packages to return (default 25, capped at 25).
    """
    res = queries.rank_critical_packages(limit=min(limit, 25))
    return json.dumps(res, indent=2)


@mcp.tool()
def find_owner(service: str) -> str:
    """
    Finds the engineering team that owns a service and lists all other
    microservices within their domain responsibility.
    
    Args:
        service: Name of the microservice (e.g. 'auth-service').
    """
    res = queries.find_owner(service=service)
    return json.dumps(res, indent=2)


@mcp.tool()
def similar_past_decisions(vuln_id: str) -> str:
    """
    Searches historical triage decisions for this vulnerability ID or for
    microservices impacted by this vulnerability to provide prior human context.
    
    Args:
        vuln_id: Vulnerability identifier to check past triage history for.
    """
    res = queries.similar_past_decisions(vuln_id=vuln_id)
    return json.dumps(res, indent=2)


@mcp.tool()
def compute_risk(vuln_id: str) -> str:
    """
    Computes a deterministic, explainable graph-aware risk score (0.0 to 10.0 scale)
    derived from graph components:
      score = 10.0 * (cvss_norm * exposure * data_sensitivity * blast_radius_factor) * critical_path_multiplier
    Returns the final score, suggested verdict, and all individual component factors.
    
    Args:
        vuln_id: Vulnerability identifier to calculate graph risk for.
    """
    res = queries.compute_risk(vuln_id=vuln_id)
    return json.dumps(res, indent=2)


@mcp.tool()
def propose_action(vuln_id: str, action_type: str, rationale: str, evidence: List[str]) -> str:
    """
    STAGED WRITE ACTION (Human-in-the-Loop):
    Stages a proposed mitigation or ticket for human approval by writing a Decision node
    into FalkorDB with status 'pending'.
    
    The AI Agent CAN NEVER execute tickets or changes directly.
    A human security lead must approve via POST /approve/{decision_id}.
    
    Args:
        vuln_id: Vulnerability ID being triaged (e.g. 'CVE-2023-SLEEPER-01').
        action_type: Recommended action: 'patch_immediately', 'schedule_maintenance', or 'deprioritize'.
        rationale: Security reasoning justifying this action based on graph topology evidence.
        evidence: List of graph paths and datastores proving the exploitability or isolation.
    """
    res = queries.propose_action(
        vuln_id=vuln_id,
        action_type=action_type,
        rationale=rationale,
        evidence=evidence
    )
    return json.dumps(res, indent=2)


async def get_tools_for_agent() -> List[Dict[str, Any]]:
    """
    Returns MCP tool definitions formatted as standard OpenAI/Mistral function schemas:
    {"type": "function", "function": {"name": ..., "description": ..., "parameters": ...}}
    """
    tools = await mcp.list_tools()
    mistral_tools = []
    for t in tools:
        mistral_tools.append({
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.parameters
            }
        })
    return mistral_tools


async def execute_mcp_tool(tool_name: str, arguments: Dict[str, Any]) -> str:
    """
    Executes an MCP tool by name with arguments via FastMCP and returns the string output.
    """
    call_result = await mcp.call_tool(tool_name, arguments)
    # Extract text content from MCP CallResult
    if call_result.content:
        for item in call_result.content:
            if hasattr(item, "text"):
                return item.text
    if hasattr(call_result, "structured_content") and call_result.structured_content:
        return json.dumps(call_result.structured_content)
    return str(call_result)


if __name__ == "__main__":
    # Runs standard FastMCP stdio server
    mcp.run()
