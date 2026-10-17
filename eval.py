#!/usr/bin/env python3
"""
VulnGraph Ground-Truth Evaluation Benchmark
=============================================
Demonstrates the core value proposition of VulnGraph:
Why traditional CVSS severity alone fails, and how FalkorDB graph-grounded
path traversals re-order triage decisions to protect crown jewels.

Evaluates:
  1. Planted Ground-Truth Benchmark:
     - 3 Sleepers: Medium CVSS (5.3 - 6.1) that reach internet-facing ingress
       and connect to high-sensitivity DataStores (PII / Payments).
     - 3 Decoys: Critical CVSS (9.6 - 9.8) that are isolated in internal,
       offline services with no path to sensitive data.
  2. Global Re-ordering across all ingested OSV findings:
     - Demonstrates rank delta: (Graph Risk Rank - CVSS Rank).
"""

import sys
import json
import argparse
from typing import List, Dict, Any
from schema import get_graph
from queries import compute_risk, get_finding_context


def get_all_vulnerabilities(limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve all vulnerabilities in FalkorDB with CVSS scores."""
    graph = get_graph()
    query = """
    MATCH (v:Vuln)
    OPTIONAL MATCH (v)-[:AFFECTS]->(p:Package)
    RETURN v.id AS vuln_id,
           v.cvss AS cvss,
           v.summary AS summary,
           collect(DISTINCT p.name) AS packages
    ORDER BY v.cvss DESC
    LIMIT $limit;
    """
    res = graph.ro_query(query, {"limit": limit})
    findings = []
    for row in res.result_set:
        findings.append({
            "vuln_id": row[0],
            "cvss": float(row[1]) if row[1] is not None else 0.0,
            "summary": row[2] or "",
            "packages": row[3] or [],
        })
    return findings


def run_benchmark_evaluation() -> Dict[str, Any]:
    """
    Run evaluation on the 6 ground-truth planted scenarios:
    3 Sleepers (Medium CVSS -> High Graph Risk)
    3 Decoys (Critical CVSS -> Low Graph Risk)
    """
    planted_sleepers = ["CVE-2023-SLEEPER-01", "CVE-2023-SLEEPER-02", "CVE-2023-SLEEPER-03"]
    planted_decoys = ["CVE-2021-DECOY-01", "CVE-2022-DECOY-02", "CVE-2023-DECOY-03"]

    results = []
    for vid in planted_sleepers + planted_decoys:
        risk_data = compute_risk(vid)
        ctx = get_finding_context(vid)
        category = "SLEEPER (Crown Jewel At Risk)" if vid in planted_sleepers else "DECOY (Internal / Unreachable)"
        is_critical_path = risk_data["components"]["critical_path_multiplier"] > 1.0
        results.append({
            "vuln_id": vid,
            "category": category,
            "cvss": risk_data["cvss_raw"],
            "graph_risk": risk_data["graph_risk_score"],
            "exposure": risk_data["components"]["exposure"],
            "data_sensitivity": risk_data["max_data_sensitivity"],
            "critical_path": is_critical_path,
            "action": risk_data["verdict"],
            "services": risk_data["impacted_services"],
            "packages": ctx.get("affected_packages", [])
        })

    # Sort by CVSS only (Baseline traditional scanner)
    cvss_ranked = sorted(results, key=lambda x: x["cvss"], reverse=True)
    for idx, item in enumerate(cvss_ranked, start=1):
        item["cvss_rank"] = idx

    # Sort by Graph Risk (VulnGraph)
    graph_ranked = sorted(results, key=lambda x: x["graph_risk"], reverse=True)
    for idx, item in enumerate(graph_ranked, start=1):
        item["graph_rank"] = idx
        item["rank_delta"] = item["cvss_rank"] - item["graph_rank"]

    # Inversion verification
    sleeper_min_risk = min(item["graph_risk"] for item in results if "SLEEPER" in item["category"])
    decoy_max_risk = max(item["graph_risk"] for item in results if "DECOY" in item["category"])
    inversion_success = sleeper_min_risk > decoy_max_risk

    return {
        "benchmark_results": graph_ranked,
        "sleeper_min_risk": sleeper_min_risk,
        "decoy_max_risk": decoy_max_risk,
        "inversion_success": inversion_success
    }


def run_full_corpus_evaluation(sample_limit: int = 50) -> Dict[str, Any]:
    """
    Score the larger corpus of OSV CVEs alongside planted benchmarks
    to show real-world re-ranking across hundreds of vulnerabilities.
    """
    all_vulns = get_all_vulnerabilities(limit=sample_limit)
    evaluated = []

    for v in all_vulns:
        vid = v["vuln_id"]
        risk_data = compute_risk(vid)
        is_critical_path = risk_data["components"]["critical_path_multiplier"] > 1.0
        evaluated.append({
            "vuln_id": vid,
            "cvss": risk_data["cvss_raw"],
            "graph_risk": risk_data["graph_risk_score"],
            "critical_path": is_critical_path,
            "action": risk_data["verdict"],
            "services": len(risk_data["impacted_services"]),
            "packages": v["packages"],
        })

    # Rank by CVSS
    by_cvss = sorted(evaluated, key=lambda x: x["cvss"], reverse=True)
    for idx, item in enumerate(by_cvss, start=1):
        item["cvss_rank"] = idx

    # Rank by Graph Risk
    by_graph = sorted(evaluated, key=lambda x: x["graph_risk"], reverse=True)
    for idx, item in enumerate(by_graph, start=1):
        item["graph_rank"] = idx
        item["rank_delta"] = item["cvss_rank"] - item["graph_rank"]

    return {
        "total_evaluated": len(evaluated),
        "top_by_graph": by_graph[:10],
        "all_ranked": by_graph
    }


def format_markdown_table(benchmark_results: List[Dict[str, Any]]) -> str:
    """Format benchmark results into Markdown table for README."""
    lines = [
        "| Vulnerability ID | Type | CVSS (Naive) | CVSS Rank | Graph Risk | Graph Rank | Rank Delta | Triage Action | Critical Attack Path? |",
        "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- | :---: |"
    ]
    for r in benchmark_results:
        delta_str = f"+{r['rank_delta']}" if r['rank_delta'] > 0 else str(r['rank_delta'])
        path_str = "🔥 YES" if r['critical_path'] else "🛡️ NO"
        cat_badge = "🚨 Sleeper" if "SLEEPER" in r['category'] else "💤 Decoy"
        lines.append(
            f"| `{r['vuln_id']}` | {cat_badge} | **{r['cvss']}** | #{r['cvss_rank']} | **{r['graph_risk']}** | #{r['graph_rank']} | `{delta_str}` | `{r['action']}` | {path_str} |"
        )
    return "\n".join(lines)


def print_ascii_report(bench: Dict[str, Any]):
    """Print readable terminal report."""
    results = bench["benchmark_results"]
    print("\n" + "=" * 90)
    print("VULNGRAPH GROUND-TRUTH EVALUATION REPORT (FalkorDB Graph Hacks Track 01)")
    print("=" * 90)
    print(f"{'Vulnerability ID':<22} | {'CVSS':<6} | {'CVSS#':<6} | {'GraphRisk':<10} | {'Graph#':<6} | {'Delta':<7} | {'Verdict Action':<18}")
    print("-" * 90)
    for r in results:
        delta_str = f"+{r['rank_delta']}" if r['rank_delta'] > 0 else str(r['rank_delta'])
        print(f"{r['vuln_id']:<22} | {r['cvss']:<6.1f} | #{r['cvss_rank']:<5} | {r['graph_risk']:<10.2f} | #{r['graph_rank']:<5} | {delta_str:<7} | {r['action']:<18}")
    print("=" * 90)

    print("\n📊 KEY REORDERING METRICS:")
    print(f"  • Lowest Sleeper Graph Risk Score : {bench['sleeper_min_risk']:.2f}")
    print(f"  • Highest Decoy Graph Risk Score  : {bench['decoy_max_risk']:.2f}")
    if bench["inversion_success"]:
        print("  • Separation Margin               : +{:.2f} pts".format(bench['sleeper_min_risk'] - bench['decoy_max_risk']))
        print("  • Evaluation Status               : [PASSED] 100% Correct Re-ordering")
        print("    -> Every planted sleeper safely displaced critical-CVSS internal decoys.")
    else:
        print("  • Evaluation Status               : [FAILED] Inversion threshold not met.")
    print("=" * 90 + "\n")


def main():
    parser = argparse.ArgumentParser(description="VulnGraph Evaluation Benchmark")
    parser.add_argument("--markdown", action="store_true", help="Print Markdown table output for README")
    parser.add_argument("--save-json", type=str, default="", help="Path to save evaluation results as JSON")
    parser.add_argument("--full-corpus", action="store_true", help="Also evaluate against full OSV corpus")
    args = parser.parse_args()

    bench = run_benchmark_evaluation()
    print_ascii_report(bench)

    if args.markdown:
        print("\n### Markdown Table for Documentation:\n")
        print(format_markdown_table(bench["benchmark_results"]))

    if args.full_corpus:
        print("\nScoring full graph corpus...")
        corpus = run_full_corpus_evaluation(sample_limit=100)
        print(f"Successfully evaluated {corpus['total_evaluated']} vulnerabilities across the live FalkorDB graph.")
        print(f"Top 5 prioritized findings by Graph Risk:")
        for idx, item in enumerate(corpus['top_by_graph'][:5], 1):
            print(f"  #{idx}: {item['vuln_id']} -> Graph Risk: {item['graph_risk']} (CVSS: {item['cvss']}, Action: {item['action']})")

    if args.save_json:
        with open(args.save_json, "w") as f:
            json.dump(bench, f, indent=2)
        print(f"\nSaved evaluation metrics to {args.save_json}")


if __name__ == "__main__":
    main()
