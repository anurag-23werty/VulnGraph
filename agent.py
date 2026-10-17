"""
VulnGraph Agent Loop Module using Groq AI (LPU ultra-fast inference) and FastMCP tools.

Features:
- Reads GROQ_API_KEY and GROQ_MODEL from environment (.env).
- Converts FastMCP tools to standard Groq function calling format.
- Multi-step reasoning loop (max 8 steps, temperature 0.1).
- Step-by-step trace logging for UI visualization.
- Pydantic schema validation with single retry on invalid JSON.
- Exponential backoff for rate limits (429) and server errors (5xx).
- Offline graph engine fallback when API key is unconfigured.
"""

import os
import sys
import json
import time
import re
import asyncio
from typing import List, Dict, Any, Optional
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Groq SDK import
from groq import Groq

from models import FindingVerdict, TriageReport, TraceStep, TriageResponse
from mcp_server import get_tools_for_agent, execute_mcp_tool
import queries

BASE_DIR = Path(__file__).resolve().parent
SYSTEM_PROMPT_PATH = BASE_DIR / "prompts" / "system.md"

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile").strip()
MAX_STEPS = 8
TEMPERATURE = 0.1


def load_system_prompt() -> str:
    """Loads system prompt from prompts/system.md."""
    if SYSTEM_PROMPT_PATH.exists():
        return SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    return (
        "You are VulnGraph, an expert security triage agent. "
        "Ground every verdict in graph evidence using MCP tools."
    )


def clean_json_text(text: str) -> str:
    """Strips markdown code blocks and whitespace from LLM output."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
        text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)
    return text.strip()


async def run_deterministic_triage(vuln_ids: List[str]) -> TriageResponse:
    """
    Deterministic Graph Engine:
    Executes the exact MCP graph tools sequentially to triage findings.
    Used when GROQ_API_KEY is not set or in deterministic test mode.
    """
    start_time = time.time()
    trace: List[TraceStep] = []
    findings: List[FindingVerdict] = []
    step_num = 1

    for vid in vuln_ids:
        # Step: get finding context
        t0 = time.time()
        ctx_raw = await execute_mcp_tool("get_finding_context", {"vuln_id": vid})
        ctx = json.loads(ctx_raw)
        trace.append(TraceStep(
            step=step_num,
            call_type="tool_call",
            tool_name="get_finding_context",
            arguments={"vuln_id": vid},
            result=ctx,
            timestamp=t0
        ))
        step_num += 1

        if not ctx.get("found"):
            continue

        # Step: blast radius
        t1 = time.time()
        radius_raw = await execute_mcp_tool("blast_radius", {"vuln_id": vid})
        radius = json.loads(radius_raw)
        trace.append(TraceStep(
            step=step_num,
            call_type="tool_call",
            tool_name="blast_radius",
            arguments={"vuln_id": vid},
            result=radius,
            timestamp=t1
        ))
        step_num += 1

        # Step: compute risk
        t2 = time.time()
        risk_raw = await execute_mcp_tool("compute_risk", {"vuln_id": vid})
        risk = json.loads(risk_raw)
        trace.append(TraceStep(
            step=step_num,
            call_type="tool_call",
            tool_name="compute_risk",
            arguments={"vuln_id": vid},
            result=risk,
            timestamp=t2
        ))
        step_num += 1

        # Step: find owners for impacted services
        impacted = radius.get("impacted_services", [])
        owning_teams = set()
        for svc in impacted[:3]:
            owner_raw = await execute_mcp_tool("find_owner", {"service": svc})
            owner = json.loads(owner_raw)
            if owner.get("found") and owner.get("team"):
                owning_teams.add(owner["team"])

        decision_id = None
        # Stage action if verdict is patch_immediately or schedule_maintenance
        if risk.get("verdict") in ("patch_immediately", "schedule_maintenance"):
            t3 = time.time()
            action_raw = await execute_mcp_tool("propose_action", {
                "vuln_id": vid,
                "action_type": risk["verdict"],
                "rationale": f"Graph risk {risk['graph_risk_score']} (Exposure: {risk['components']['exposure']}, Data: {risk['components']['data_sensitivity']}).",
                "evidence": risk.get("evidence_paths", [])
            })
            action_data = json.loads(action_raw)
            decision_id = action_data.get("decision_id")
            trace.append(TraceStep(
                step=step_num,
                call_type="tool_call",
                tool_name="propose_action",
                arguments={"vuln_id": vid, "action_type": risk["verdict"]},
                result=action_data,
                timestamp=t3
            ))
            step_num += 1

        # Extract OSV metadata from context
        pkg_name = ctx["packages"][0]["name"] if ctx.get("packages") else "unknown"
        pkg_ver = ctx["packages"][0]["version"] if ctx.get("packages") else "unknown"
        fix_ver = ctx.get("fix_version", "unknown")
        summary_text = ctx.get("summary", "")
        is_planted = "SLEEPER" in vid or "DECOY" in vid
        source_label = "Benchmark Planted" if is_planted else "OSV.dev"
        osv_link = f"https://osv.dev/vulnerability/{vid}" if not is_planted else f"Planted {vid}"

        # Rationale formulation citing OSV source and graph impact
        if is_planted:
            prefix = f"Benchmark evaluation scenario {vid}"
        else:
            prefix = f"OSV.dev finding {vid} ({summary_text[:70]}...)"

        rationale = (
            f"{prefix} affecting package '{pkg_name}@{pkg_ver}' in service(s) {', '.join(impacted)}. "
            f"Internet exposure: {risk['has_internet_exposure']}. "
            f"Max data sensitivity: '{risk['max_data_sensitivity']}'. "
            f"Fix version: {fix_ver}. "
            f"Deterministic graph risk score: {risk['graph_risk_score']}/10.0."
        )

        findings.append(FindingVerdict(
            vuln_id=vid,
            source=source_label,
            summary=summary_text,
            package_name=pkg_name,
            package_version=pkg_ver,
            fix_version=fix_ver,
            osv_url=osv_link,
            cvss_raw=ctx["cvss"],
            graph_risk_score=risk["graph_risk_score"],
            verdict=risk["verdict"],
            impacted_services=impacted,
            owning_teams=sorted(list(owning_teams)) if owning_teams else ["unassigned"],
            has_internet_exposure=risk["has_internet_exposure"],
            max_data_sensitivity=risk["max_data_sensitivity"],
            evidence_paths=risk.get("evidence_paths", []),
            decision_id=decision_id,
            rationale=rationale
        ))

    # Rank findings by graph risk score descending
    findings.sort(key=lambda x: x.graph_risk_score, reverse=True)

    summary = (
        f"Triaged {len(findings)} findings using FalkorDB Cypher traversals. "
        f"Reordered priorities based on true attack paths and crown-jewel exposure."
    )
    report = TriageReport(summary=summary, findings=findings)

    trace.append(TraceStep(
        step=step_num,
        call_type="verdict",
        tool_name="TriageReport",
        arguments=None,
        result=report.model_dump(),
        timestamp=time.time()
    ))

    # Baseline comparison (CVSS only ranking vs Graph ranking)
    baseline_ranking = sorted(
        [{"vuln_id": f.vuln_id, "cvss": f.cvss_raw, "verdict": "critical" if f.cvss_raw >= 9.0 else "medium"} for f in findings],
        key=lambda x: x["cvss"],
        reverse=True
    )
    graph_ranking = [
        {"vuln_id": f.vuln_id, "graph_risk": f.graph_risk_score, "verdict": f.verdict, "exposure": f.has_internet_exposure}
        for f in findings
    ]

    total_time_ms = round((time.time() - start_time) * 1000, 2)

    return TriageResponse(
        report=report,
        trace=trace,
        steps_taken=len(trace),
        latency_ms=total_time_ms,
        baseline_ranking=baseline_ranking,
        graph_ranking=graph_ranking
    )


async def run_groq_agent_triage(vuln_ids: List[str], api_key: Optional[str] = None) -> TriageResponse:
    """
    Executes the autonomous Groq AI agent loop with FastMCP graph tools.
    """
    effective_key = api_key or GROQ_API_KEY
    if not effective_key or effective_key.startswith("your_"):
        # Fall back gracefully to deterministic graph engine
        return await run_deterministic_triage(vuln_ids)

    start_time = time.time()
    client = Groq(api_key=effective_key)
    system_prompt = load_system_prompt()
    tools = await get_tools_for_agent()

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                f"Triage the following security vulnerability IDs across our architecture: {json.dumps(vuln_ids)}. "
                "Investigate each finding via MCP graph tools, compute the graph-adjusted risk, map ownership, "
                "stage proposed actions for critical findings, and return your final response strictly as the required JSON schema."
            )
        }
    ]

    trace: List[TraceStep] = []
    step = 0
    triage_report: Optional[TriageReport] = None
    retry_count = 0

    while step < MAX_STEPS:
        step += 1
        t_call_start = time.time()

        # Call Groq chat completion with backoff
        response = None
        for attempt in range(3):
            try:
                trace.append(TraceStep(
                    step=step,
                    call_type="llm_call",
                    tool_name=None,
                    arguments={"model": GROQ_MODEL, "temperature": TEMPERATURE, "message_count": len(messages)},
                    result=None,
                    timestamp=time.time()
                ))
                response = client.chat.completions.create(
                    model=GROQ_MODEL,
                    messages=messages,
                    tools=tools,
                    tool_choice="auto",
                    temperature=TEMPERATURE
                )
                break
            except Exception as e:
                err_msg = str(e).lower()
                is_rate_limit = "429" in err_msg or "rate" in err_msg
                is_server_err = "50" in err_msg or "timeout" in err_msg
                if (is_rate_limit or is_server_err) and attempt < 2:
                    wait_sec = 2 ** (attempt + 1)
                    await asyncio.sleep(wait_sec)
                else:
                    trace.append(TraceStep(
                        step=step,
                        call_type="error",
                        tool_name=None,
                        arguments=None,
                        result=f"Groq API error: {str(e)}",
                        timestamp=time.time()
                    ))
                    # On permanent error, fall back gracefully to deterministic engine
                    return await run_deterministic_triage(vuln_ids)

        if not response or not response.choices:
            break

        assistant_choice = response.choices[0]
        assistant_msg = assistant_choice.message

        # Case 1: Model requests tool calls
        if hasattr(assistant_msg, "tool_calls") and assistant_msg.tool_calls:
            # Append assistant message with tool calls to conversation history
            messages.append({
                "role": "assistant",
                "content": assistant_msg.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments
                        }
                    }
                    for tc in assistant_msg.tool_calls
                ]
            })

            for tc in assistant_msg.tool_calls:
                fn_name = tc.function.name
                try:
                    fn_args = json.loads(tc.function.arguments) if isinstance(tc.function.arguments, str) else tc.function.arguments
                except Exception:
                    fn_args = {}

                # Execute MCP Tool
                tool_output_str = await execute_mcp_tool(fn_name, fn_args)
                try:
                    parsed_res = json.loads(tool_output_str)
                except Exception:
                    parsed_res = tool_output_str

                trace.append(TraceStep(
                    step=step,
                    call_type="tool_call",
                    tool_name=fn_name,
                    arguments=fn_args,
                    result=parsed_res,
                    timestamp=time.time()
                ))

                # Append tool result to messages
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": fn_name,
                    "content": tool_output_str
                })

            continue

        # Case 2: Model returns final response text
        content = assistant_msg.content or ""
        clean_content = clean_json_text(content)

        try:
            triage_report = TriageReport.model_validate_json(clean_content)
            trace.append(TraceStep(
                step=step,
                call_type="verdict",
                tool_name="TriageReport",
                arguments=None,
                result=triage_report.model_dump(),
                timestamp=time.time()
            ))
            break
        except Exception as validation_err:
            if retry_count == 0:
                retry_count += 1
                trace.append(TraceStep(
                    step=step,
                    call_type="retry",
                    tool_name=None,
                    arguments={"raw_output": content[:200]},
                    result=f"Validation failed: {str(validation_err)}. Retrying...",
                    timestamp=time.time()
                ))
                messages.append({
                    "role": "assistant",
                    "content": content
                })
                messages.append({
                    "role": "user",
                    "content": (
                        f"Your output failed JSON schema validation: {str(validation_err)}. "
                        "Please output ONLY raw JSON strictly adhering to the schema."
                    )
                })
                continue
            else:
                # If retry also fails, fall back to deterministic engine
                return await run_deterministic_triage(vuln_ids)

    if not triage_report:
        return await run_deterministic_triage(vuln_ids)

    # Calculate baseline and graph comparisons
    baseline_ranking = sorted(
        [{"vuln_id": f.vuln_id, "cvss": f.cvss_raw, "verdict": "critical" if f.cvss_raw >= 9.0 else "medium"} for f in triage_report.findings],
        key=lambda x: x["cvss"],
        reverse=True
    )
    graph_ranking = [
        {"vuln_id": f.vuln_id, "graph_risk": f.graph_risk_score, "verdict": f.verdict, "exposure": f.has_internet_exposure}
        for f in triage_report.findings
    ]

    total_time_ms = round((time.time() - start_time) * 1000, 2)

    return TriageResponse(
        report=triage_report,
        trace=trace,
        steps_taken=len(trace),
        latency_ms=total_time_ms,
        baseline_ranking=baseline_ranking,
        graph_ranking=graph_ranking
    )


# Backward-compatible aliases
run_mistral_agent_triage = run_groq_agent_triage
run_agent_triage = run_groq_agent_triage
