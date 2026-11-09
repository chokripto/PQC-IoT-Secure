import pytest

from scripts.benchmark_iot import summarize_ns


def test_timing_summary_uses_nearest_rank_p95():
    values = list(range(1, 101))
    summary = summarize_ns(values)

    assert summary == {
        "samples": 100,
        "min_ns": 1,
        "median_ns": 50,
        "mean_ns": 50,
        "p95_ns": 95,
        "max_ns": 100,
    }


def test_timing_summary_rejects_empty_input():
    with pytest.raises(ValueError, match="At least one"):
        summarize_ns([])
