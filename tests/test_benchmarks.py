from scripts.benchmark_action_flow import run_benchmark


def test_signed_action_benchmark_passes_without_provider_delay() -> None:
    result = run_benchmark(iterations=1, provider_latency_seconds=0)

    assert result["all_instant_approved"] is True
    assert result["all_liveness_approved"] is True
    assert result["instant_median_seconds"] < 3
    assert result["liveness_median_seconds"] < 30
    assert result["target_pass"] is True
