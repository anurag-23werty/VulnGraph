"""
Tests for the Ground-Truth Evaluation Benchmark (eval.py).
"""

from eval import run_benchmark_evaluation, run_full_corpus_evaluation, format_markdown_table


def test_benchmark_evaluation_inversion():
    """
    Verify that 100% of sleepers rank strictly above all decoys in Graph Risk,
    reversing the naive CVSS prioritization.
    """
    bench = run_benchmark_evaluation()
    assert bench["inversion_success"] is True
    assert bench["sleeper_min_risk"] > bench["decoy_max_risk"]
    assert bench["sleeper_min_risk"] >= 7.0  # Must be 'patch_immediately'
    assert bench["decoy_max_risk"] <= 2.0    # Must be 'deprioritize'

    # Check that rank deltas for sleepers are positive and decoys are negative
    for item in bench["benchmark_results"]:
        if "SLEEPER" in item["category"]:
            assert item["rank_delta"] > 0
            assert item["action"] == "patch_immediately"
            assert item["critical_path"] is True
        elif "DECOY" in item["category"]:
            assert item["rank_delta"] < 0
            assert item["action"] == "deprioritize"
            assert item["critical_path"] is False


def test_markdown_table_generation():
    """Verify that markdown table formatting produces valid markdown output."""
    bench = run_benchmark_evaluation()
    md = format_markdown_table(bench["benchmark_results"])
    assert "| Vulnerability ID |" in md
    assert "CVE-2023-SLEEPER-01" in md
    assert "CVE-2021-DECOY-01" in md
    assert "patch_immediately" in md
    assert "deprioritize" in md


def test_full_corpus_evaluation():
    """Verify evaluation against live graph samples."""
    corpus = run_full_corpus_evaluation(sample_limit=20)
    assert corpus["total_evaluated"] >= 6
    assert len(corpus["top_by_graph"]) <= 10
