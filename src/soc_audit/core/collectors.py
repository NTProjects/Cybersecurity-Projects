"""Real-time collectors for streaming telemetry events into the dashboard.

This module provides collectors that produce TelemetryEvent objects for
display in the SOC dashboard. Collectors run in background threads and
emit events through a thread-safe queue.
"""
from __future__ import annotations

import queue
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None  # type: ignore


@dataclass
class TelemetryEvent:
    """A telemetry event produced by collectors."""

    timestamp: datetime
    source: str  # "metrics", "logs", "sockets", "engine"
    severity: str  # "info", "low", "medium", "high", "critical"
    title: str
    module: str  # "collector_metrics", "collector_logs", etc.
    evidence: dict[str, Any] = field(default_factory=dict)
    mitre_tactics: list[str] | None = None
    mitre_techniques: list[str] | None = None
    mitre_ids: list[str] | None = None
    rba_score: int | None = None
    rba_breakdown: dict[str, Any] | None = None


class MetricsCollector:
    """Collector for system metrics using psutil."""

    def __init__(
        self,
        interval_ms: int = 1000,
        metrics_callback: Callable[[dict[str, Any]], None] | None = None,
    ):
        """
        Initialize the metrics collector.

        Args:
            interval_ms: Collection interval in milliseconds.
            metrics_callback: Optional callback to update metrics panel directly.
        """
        self.interval_ms = interval_ms
        self.metrics_callback = metrics_callback
        self._running = False
        self._thread: threading.Thread | None = None
        self._last_net_io = None
        self._last_net_time = None

    def start(self) -> None:
        """Start the collector thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the collector thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        """Main collection loop."""
        if psutil is None:
            return

        while self._running:
            try:
                # Collect metrics
                cpu_percent = psutil.cpu_percent(interval=0.1)
                mem = psutil.virtual_memory()
                mem_percent = mem.percent

                # Network I/O (calculate delta per second)
                net_io = psutil.net_io_counters()
                now = time.time()
                net_in_bps = 0
                net_out_bps = 0

                if self._last_net_io and self._last_net_time:
                    elapsed = now - self._last_net_time
                    if elapsed > 0:
                        net_in_bps = int((net_io.bytes_recv - self._last_net_io.bytes_recv) / elapsed)
                        net_out_bps = int((net_io.bytes_sent - self._last_net_io.bytes_sent) / elapsed)

                self._last_net_io = net_io
                self._last_net_time = now

                # Connection count
                conn_count = 0
                try:
                    connections = psutil.net_connections(kind="inet")
                    conn_count = len([c for c in connections if c.status == "ESTABLISHED"])
                except (psutil.AccessDenied, OSError):
                    # On some systems, we can't enumerate connections
                    conn_count = -1  # Indicate N/A

                # Build metrics dict for callback
                metrics = {
                    "cpu_percent": cpu_percent,
                    "mem_percent": mem_percent,
                    "net_in_bps": net_in_bps,
                    "net_out_bps": net_out_bps,
                    "connections": conn_count if conn_count >= 0 else None,
                }

                # Call metrics callback if available
                if self.metrics_callback:
                    try:
                        self.metrics_callback(metrics)
                    except Exception:
                        pass  # Ignore callback errors

            except Exception:
                pass  # Ignore errors in collector

            # Sleep until next interval
            time.sleep(self.interval_ms / 1000.0)


class SocketsFallbackCollector:
    """Fallback collector when psutil is unavailable."""

    def __init__(self, interval_ms: int = 1000):
        """Initialize the fallback collector."""
        self.interval_ms = interval_ms
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the collector thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the collector thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        """Main collection loop (minimal implementation)."""
        while self._running:
            # Emit a simple N/A metrics event periodically
            time.sleep(self.interval_ms / 1000.0)


class LogTailCollector:
    """Collector for tailing authentication logs."""

    def __init__(
        self,
        log_file: str | Path | None,
        interval_ms: int = 500,
        failure_threshold: int = 5,
        window_seconds: int = 60,
    ):
        """
        Initialize the log tail collector.

        Args:
            log_file: Path to auth log file (None disables collector).
            interval_ms: Check interval in milliseconds.
            failure_threshold: Minimum failures to trigger alert.
            window_seconds: Sliding window size for aggregation.
        """
        self.log_file = Path(log_file) if log_file else None
        self.interval_ms = interval_ms
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        self._running = False
        self._thread: threading.Thread | None = None
        self._last_position = 0
        self._failure_window: list[tuple[float, str | None, str | None]] = []  # (time, username, ip)

        # Patterns matching log_analyzer
        self.failed_password_pattern = re.compile(
            r"Failed password for (?P<username>\S+) from (?P<ip>\S+)"
        )
        self.auth_failure_pattern = re.compile(
            r"authentication failure.*?rhost=(?P<ip>\S+)"
        )
        self.invalid_user_pattern = re.compile(
            r"Invalid user (?P<username>\S+) from (?P<ip>\S+)"
        )

    def start(self) -> None:
        """Start the collector thread."""
        if not self.log_file or not self.log_file.exists():
            return  # Disable if no file
        if self._running:
            return
        self._running = True
        self._last_position = self.log_file.stat().st_size if self.log_file.exists() else 0
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the collector thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        """Main collection loop."""
        if not self.log_file or not self.log_file.exists():
            return

        while self._running:
            try:
                if not self.log_file.exists():
                    time.sleep(self.interval_ms / 1000.0)
                    continue

                # Read new lines
                with self.log_file.open("r", encoding="utf-8", errors="ignore") as f:
                    f.seek(self._last_position)
                    new_lines = f.readlines()
                    self._last_position = f.tell()

                # Process new lines
                now = time.time()
                for line in new_lines:
                    self._process_log_line(line, now)

                # Clean old entries from window
                cutoff = now - self.window_seconds
                self._failure_window = [(t, u, ip) for t, u, ip in self._failure_window if t >= cutoff]

                # Check for threshold violations
                self._check_thresholds(now)

            except Exception:
                pass  # Ignore errors

            time.sleep(self.interval_ms / 1000.0)

    def _process_log_line(self, line: str, timestamp: float) -> None:
        """Process a single log line and add failures to window."""
        # Try failed password pattern
        match = self.failed_password_pattern.search(line)
        if match:
            username = match.group("username")
            source_ip = match.group("ip")
            self._failure_window.append((timestamp, username, source_ip))
            return

        # Try auth failure pattern
        match = self.auth_failure_pattern.search(line)
        if match:
            source_ip = match.group("ip")
            self._failure_window.append((timestamp, None, source_ip))
            return

        # Try invalid user pattern
        match = self.invalid_user_pattern.search(line)
        if match:
            username = match.group("username")
            source_ip = match.group("ip")
            self._failure_window.append((timestamp, username, source_ip))
            return

    def _check_thresholds(self, now: float) -> None:
        """Check if any (user, ip) pairs exceed threshold (emitted via queue by manager)."""
        # Aggregate by (username, ip) in current window
        counts: dict[tuple[str | None, str | None], int] = defaultdict(int)
        for _, username, ip in self._failure_window:
            counts[(username, ip)] += 1

        # Note: Actual event emission happens in CollectorManager
        # This is just the aggregation logic
        self._recent_violations = [
            (username, ip, count)
            for (username, ip), count in counts.items()
            if count >= self.failure_threshold
        ]

    def get_recent_violations(self) -> list[tuple[str | None, str | None, int]]:
        """Get recent threshold violations (called by manager)."""
        return getattr(self, "_recent_violations", [])


class CollectorManager:
    """Manager for coordinating multiple collectors."""

    def __init__(
        self,
        event_queue: queue.Queue[TelemetryEvent],
        config: dict[str, Any],
        metrics_callback: Callable[[dict[str, Any]], None] | None = None,
    ):
        """
        Initialize the collector manager.

        Args:
            event_queue: Thread-safe queue for telemetry events.
            config: Collector configuration dict.
            metrics_callback: Optional callback for direct metrics updates.
        """
        self.event_queue = event_queue
        self.config = config
        self.metrics_callback = metrics_callback
        self._collectors: list[Any] = []
        self._running = False
        self._last_log_alert_time: dict[tuple[str | None, str | None], float] = {}

        # Initialize collectors based on config
        if config.get("enabled", True):
            metrics_interval = config.get("metrics_interval_ms", 1000)
            log_interval = config.get("log_interval_ms", 500)
            auth_log_file = config.get("auth_log_file")

            # Metrics collector (psutil-based or fallback)
            if psutil is not None:
                self._metrics_collector = MetricsCollector(metrics_interval, metrics_callback)
            else:
                self._metrics_collector = SocketsFallbackCollector(metrics_interval)

            # Log tail collector (if file configured)
            if auth_log_file:
                self._log_collector = LogTailCollector(
                    auth_log_file,
                    log_interval,
                    failure_threshold=config.get("log_failure_threshold", 5),
                )
            else:
                self._log_collector = None

            self._collectors = [c for c in [self._metrics_collector, self._log_collector] if c is not None]

    def start(self) -> None:
        """Start all collectors."""
        if self._running:
            return
        self._running = True

        # Start collectors
        for collector in self._collectors:
            try:
                collector.start()
            except Exception:
                pass  # Ignore start errors

        # Start monitoring thread for log violations
        if self._log_collector:
            self._monitor_thread = threading.Thread(target=self._monitor_log_violations, daemon=True)
            self._monitor_thread.start()

        # Emit initial status
        if not self._log_collector:
            event = TelemetryEvent(
                timestamp=datetime.utcnow(),
                source="logs",
                severity="info",
                title="Log collector disabled (no file configured)",
                module="collector_manager",
                evidence={},
            )
            try:
                self.event_queue.put_nowait(event)
            except Exception:
                pass

    def stop(self) -> None:
        """Stop all collectors."""
        self._running = False
        for collector in self._collectors:
            try:
                collector.stop()
            except Exception:
                pass

    def _monitor_log_violations(self) -> None:
        """Monitor log collector for threshold violations."""
        while self._running:
            try:
                if self._log_collector:
                    violations = self._log_collector.get_recent_violations()
                    now = time.time()

                    for username, ip, count in violations:
                        key = (username, ip)
                        # Throttle alerts (emit once per 30 seconds per key)
                        last_alert = self._last_log_alert_time.get(key, 0)
                        if now - last_alert < 30:
                            continue

                        self._last_log_alert_time[key] = now

                        # Build event
                        title_parts = []
                        if username:
                            title_parts.append(f"User '{username}'")
                        else:
                            title_parts.append("Unknown user")
                        if ip:
                            title_parts.append(f"from {ip}")
                        title_parts.append(f"has {count} repeated authentication failures")

                        event = TelemetryEvent(
                            timestamp=datetime.utcnow(),
                            source="logs",
                            severity="high",
                            title="Repeated authentication failures detected",
                            module="collector_logs",
                            evidence={
                                "username": username,
                                "source_ip": ip,
                                "failure_count": count,
                            },
                            mitre_tactics=["Credential Access"],
                            mitre_techniques=["Brute Force"],
                            mitre_ids=["T1110"],
                        )

                        try:
                            self.event_queue.put_nowait(event)
                        except Exception:
                            pass

            except Exception:
                pass

            time.sleep(2.0)  # Check every 2 seconds
