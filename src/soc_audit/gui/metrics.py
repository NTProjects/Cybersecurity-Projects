"""System metrics helper for the SOC Audit GUI dashboard.

This module provides system telemetry (CPU, memory, network, connections)
using psutil when available. Falls back gracefully with N/A values if
psutil is not installed or access is denied.

No exceptions are raised to callers; errors are returned in the result dict.
"""
from __future__ import annotations

import time
from typing import Any

# Module-level cache for network rate calculation
_prev_net: dict[str, int] | None = None
_prev_time: float | None = None


def get_system_metrics() -> dict[str, Any]:
    """
    Get current system metrics.

    Returns a dictionary with keys:
        - cpu_percent: float | None
        - memory_percent: float | None
        - net_in_bps: int | None (bytes per second)
        - net_out_bps: int | None (bytes per second)
        - active_conns: int | None
        - error: str | None

    If psutil is unavailable or access is denied, affected values
    will be None and an error message may be set.
    """
    global _prev_net, _prev_time

    result: dict[str, Any] = {
        "cpu_percent": None,
        "memory_percent": None,
        "net_in_bps": None,
        "net_out_bps": None,
        "active_conns": None,
        "error": None,
    }

    try:
        import psutil
    except ImportError:
        result["error"] = "psutil not installed"
        return result

    errors: list[str] = []

    # CPU usage (non-blocking)
    try:
        result["cpu_percent"] = psutil.cpu_percent(interval=None)
    except Exception as e:
        errors.append(f"CPU: {e}")

    # Memory usage
    try:
        mem = psutil.virtual_memory()
        result["memory_percent"] = mem.percent
    except Exception as e:
        errors.append(f"Memory: {e}")

    # Network I/O (calculate rate from delta)
    try:
        net = psutil.net_io_counters()
        current_time = time.time()

        if _prev_net is not None and _prev_time is not None:
            delta_time = current_time - _prev_time
            if delta_time > 0:
                delta_in = net.bytes_recv - _prev_net["bytes_recv"]
                delta_out = net.bytes_sent - _prev_net["bytes_sent"]
                result["net_in_bps"] = int(delta_in / delta_time)
                result["net_out_bps"] = int(delta_out / delta_time)

        # Update cache for next call
        _prev_net = {"bytes_recv": net.bytes_recv, "bytes_sent": net.bytes_sent}
        _prev_time = current_time

    except Exception as e:
        errors.append(f"Network: {e}")

    # Active connections
    try:
        conns = psutil.net_connections(kind="inet")
        result["active_conns"] = len(conns)
    except psutil.AccessDenied:
        # Common on Windows/macOS without elevated privileges
        result["active_conns"] = None
        errors.append("Connections: access denied")
    except Exception as e:
        errors.append(f"Connections: {e}")

    if errors:
        result["error"] = "; ".join(errors)

    return result


def format_bytes_rate(bps: int | None) -> str:
    """
    Format bytes per second to human-readable string.

    Args:
        bps: Bytes per second, or None.

    Returns:
        Formatted string like "120 KB/s" or "N/A".
    """
    if bps is None:
        return "N/A"

    if bps < 1024:
        return f"{bps} B/s"
    elif bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    elif bps < 1024 * 1024 * 1024:
        return f"{bps / (1024 * 1024):.1f} MB/s"
    else:
        return f"{bps / (1024 * 1024 * 1024):.1f} GB/s"
