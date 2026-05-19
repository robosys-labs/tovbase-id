from scripts.benchmark_action_flow import run_benchmark
from scripts.benchmark_registry_core import run_benchmark as run_registry_benchmark


def test_signed_action_benchmark_passes_without_provider_delay() -> None:
    result = run_benchmark(iterations=1, provider_latency_seconds=0)

    assert result["all_instant_approved"] is True
    assert result["all_liveness_approved"] is True
    assert result["instant_median_seconds"] < 3
    assert result["liveness_median_seconds"] < 30
    assert result["target_pass"] is True


def test_registry_core_benchmark_passes_local_targets() -> None:
    result = run_registry_benchmark(iterations=2)

    assert result["target_pass"] is True
    assert result["metrics"]["register"]["p95_seconds"] < 0.075
    assert result["metrics"]["resolve_by_did"]["p95_seconds"] < 0.02
    assert result["metrics"]["resolve_by_hash"]["p95_seconds"] < 0.02
