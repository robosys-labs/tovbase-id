from __future__ import annotations

import os
import platform
from ctypes import Structure, byref, c_size_t, c_ulong, c_void_p, sizeof
from pathlib import Path
from typing import Any

from app.config import settings


def _windows_rss_bytes() -> int | None:
    from ctypes import windll

    class ProcessMemoryCounters(Structure):
        _fields_ = [
            ("cb", c_ulong),
            ("page_fault_count", c_ulong),
            ("peak_working_set_size", c_size_t),
            ("working_set_size", c_size_t),
            ("quota_peak_paged_pool_usage", c_size_t),
            ("quota_paged_pool_usage", c_size_t),
            ("quota_peak_non_paged_pool_usage", c_size_t),
            ("quota_non_paged_pool_usage", c_size_t),
            ("pagefile_usage", c_size_t),
            ("peak_pagefile_usage", c_size_t),
        ]

    counters = ProcessMemoryCounters()
    counters.cb = sizeof(counters)
    handle = c_void_p(windll.kernel32.GetCurrentProcess())
    ok = windll.psapi.GetProcessMemoryInfo(handle, byref(counters), counters.cb)
    return int(counters.working_set_size) if ok else None


def _procfs_rss_bytes() -> int | None:
    statm = Path("/proc/self/statm")
    if not statm.exists():
        return None
    try:
        resident_pages = int(statm.read_text(encoding="utf-8").split()[1])
    except (IndexError, OSError, ValueError):
        return None
    return resident_pages * os.sysconf("SC_PAGE_SIZE")


def current_runtime_status() -> dict[str, Any]:
    rss_bytes = _windows_rss_bytes() if os.name == "nt" else _procfs_rss_bytes()
    rss_mb = round(rss_bytes / (1024 * 1024), 2) if rss_bytes is not None else None
    return {
        "implementation": "python-fastapi-reference",
        "pid": os.getpid(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "rss_bytes": rss_bytes,
        "rss_mb": rss_mb,
        "memory_target_mb": settings.api_memory_target_mb,
        "memory_within_target": None if rss_mb is None else rss_mb <= settings.api_memory_target_mb,
        "migration_candidate": "go-registry-core",
    }
