"""
Test suite for VulnGraph FastMCP Server.
Verifies all 8 MCP tools, schema conversion for Mistral, and in-process execution.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from mcp_server import mcp, get_tools_for_agent, execute_mcp_tool
from schema import get_graph


def test_mcp_tool_listing():
    """Verify that all 8 required tools are registered with FastMCP."""
    async def _test():
        tools = await mcp.list_tools()
        tool_names = [t.name for t in tools]

        expected_tools = [
            "get_finding_context",
            "blast_radius",
            "exploit_path",
            "rank_critical_packages",
            "find_owner",
            "similar_past_decisions",
            "compute_risk",
            "propose_action"
        ]

        for expected in expected_tools:
            assert expected in tool_names, f"Expected tool '{expected}' missing from FastMCP registry"

    asyncio.run(_test())


def test_mistral_tool_schemas():
    """Verify conversion of FastMCP tool schemas to Mistral function calling format."""
    async def _test():
        mistral_tools = await get_tools_for_agent()
        assert len(mistral_tools) == 8

        for t in mistral_tools:
            assert t["type"] == "function"
            fn = t["function"]
            assert "name" in fn and fn["name"]
            assert "description" in fn and fn["description"]
            assert "parameters" in fn and isinstance(fn["parameters"], dict)
            assert fn["parameters"].get("type") == "object"
            assert "properties" in fn["parameters"]

    asyncio.run(_test())


def test_execute_get_finding_context():
    async def _test():
        raw_res = await execute_mcp_tool("get_finding_context", {"vuln_id": "CVE-2023-SLEEPER-01"})
        data = json.loads(raw_res)
        assert data["found"] is True
        assert data["vuln_id"] == "CVE-2023-SLEEPER-01"
        assert data["cvss"] == 5.3
        assert "checkout-service" in data["direct_services"]

    asyncio.run(_test())


def test_execute_blast_radius():
    async def _test():
        raw_res = await execute_mcp_tool("blast_radius", {"vuln_id": "CVE-2023-SLEEPER-03"})
        data = json.loads(raw_res)
        assert data["vuln_id"] == "CVE-2023-SLEEPER-03"
        assert "api-gateway" in data["impacted_services"]
        assert data["has_internet_facing"] is True
        assert len(data["dependency_chains"]) > 0

    asyncio.run(_test())


def test_execute_exploit_path():
    async def _test():
        raw_res = await execute_mcp_tool("exploit_path", {"service": "checkout-service"})
        data = json.loads(raw_res)
        assert data["service"] == "checkout-service"
        assert data["is_internet_exposed"] is True
        assert data["max_data_sensitivity"] == "high"
        assert data["has_critical_exploit_path"] is True

    asyncio.run(_test())


def test_execute_rank_critical_packages():
    async def _test():
        raw_res = await execute_mcp_tool("rank_critical_packages", {"limit": 5})
        data = json.loads(raw_res)
        assert isinstance(data, list)
        assert len(data) <= 5
        assert len(data) > 0
        assert "package_name" in data[0]
        assert "pagerank_score" in data[0]

    asyncio.run(_test())


def test_execute_find_owner():
    async def _test():
        raw_res = await execute_mcp_tool("find_owner", {"service": "auth-service"})
        data = json.loads(raw_res)
        assert data["service"] == "auth-service"
        assert data["team"] == "identity-team"

    asyncio.run(_test())


def test_execute_similar_past_decisions():
    async def _test():
        raw_res = await execute_mcp_tool("similar_past_decisions", {"vuln_id": "CVE-2023-SLEEPER-01"})
        data = json.loads(raw_res)
        assert isinstance(data, list)
        assert len(data) >= 1
        assert any(d["decision_id"] == "dec-hist-001" for d in data)

    asyncio.run(_test())


def test_execute_compute_risk():
    async def _test():
        raw_res = await execute_mcp_tool("compute_risk", {"vuln_id": "CVE-2023-SLEEPER-01"})
        data = json.loads(raw_res)
        assert data["vuln_id"] == "CVE-2023-SLEEPER-01"
        assert "graph_risk_score" in data
        assert data["graph_risk_score"] > 7.0
        assert data["verdict"] == "patch_immediately"
        assert "components" in data
        assert data["components"]["exposure"] == 1.0

    asyncio.run(_test())


def test_execute_propose_action_staged():
    async def _test():
        raw_res = await execute_mcp_tool(
            "propose_action",
            {
                "vuln_id": "CVE-2023-SLEEPER-03",
                "action_type": "patch_immediately",
                "rationale": "Prototype pollution via express dependency reachable from api-gateway to customer PII store.",
                "evidence": ["api-gateway -> express -> lodash", "api-gateway -> customer-pII-db"]
            }
        )
        data = json.loads(raw_res)
        assert data["status"] == "pending"
        assert "decision_id" in data
        assert data["vuln_id"] == "CVE-2023-SLEEPER-03"

        # Verify directly in FalkorDB
        g = get_graph()
        res = g.query("MATCH (d:Decision {id: $id}) RETURN d.status, d.action_type", {"id": data["decision_id"]})
        assert len(res.result_set) == 1
        assert res.result_set[0][0] == "pending"

    asyncio.run(_test())
