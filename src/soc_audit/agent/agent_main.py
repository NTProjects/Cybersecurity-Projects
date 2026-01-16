"""Main agent runner for SOC Audit edge agent."""
from __future__ import annotations

import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

from soc_audit.agent.client import AgentClient
from soc_audit.agent.normalize import normalize_demo_event
from soc_audit.core.config import load_config


class AgentRunner:
    """Agent runner that maintains heartbeat and sends batched events."""

    def __init__(self, config_path: str | Path | None = None):
        """
        Initialize the agent runner.

        Args:
            config_path: Path to config file (defaults to config/default.json).
        """
        if config_path is None:
            config_path = Path("config/default.json")
        else:
            config_path = Path(config_path)

        # Load config
        try:
            full_config = load_config(config_path)
        except Exception as e:
            raise Exception(f"Failed to load config from {config_path}: {e}")

        agent_config = full_config.get("agent", {})
        if not agent_config.get("enabled", False):
            raise Exception("Agent is not enabled in config (agent.enabled must be true)")

        # Extract agent config
        self.host_id = agent_config.get("host_id")
        if not self.host_id:
            raise Exception("agent.host_id is required in config")

        self.host_name = agent_config.get("host_name")
        self.server_url = agent_config.get("server_url", "http://127.0.0.1:8001")
        self.api_key = agent_config.get("api_key", "AGENT_KEY")
        self.heartbeat_interval = agent_config.get("heartbeat_interval", 10)  # seconds
        self.batch_interval = agent_config.get("batch_interval", 5)  # seconds
        
        # Phase 8.1: Retry configuration
        self.retry_initial = agent_config.get("retry_initial_seconds", 1)
        self.retry_max = agent_config.get("retry_max_seconds", 30)

        # Initialize client
        self.client = AgentClient(self.server_url, self.api_key)

        # Phase 8.1: Connection state tracking
        self._connection_state = "DISCONNECTED"  # CONNECTED, DISCONNECTED, RECONNECTED
        self._last_connection_log_time = 0.0

        # State
        self._running = False
        self._heartbeat_thread: threading.Thread | None = None
        self._batch_thread: threading.Thread | None = None
        self._event_buffer: list[dict[str, Any]] = []

        # Signal handling
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print("\n[AGENT] Shutdown signal received, stopping...")
        self.stop()
        
        # Phase 8.1: Graceful shutdown - exit cleanly
        sys.exit(0)

    def run(self):
        """Start the agent and run until stopped."""
        if self._running:
            return

        self._running = True

        print(f"[AGENT] Starting agent for host: {self.host_id}")
        print(f"[AGENT] Server URL: {self.server_url}")
        print(f"[AGENT] Heartbeat interval: {self.heartbeat_interval}s")
        print(f"[AGENT] Batch interval: {self.batch_interval}s")

        # Start background threads
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._batch_thread = threading.Thread(target=self._batch_loop, daemon=True)

        self._heartbeat_thread.start()
        self._batch_thread.start()

        print("[AGENT] Agent running. Press Ctrl+C to stop.")

        # Keep main thread alive
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

        # Phase 8.1: Graceful shutdown - wait for threads to finish
        print("[AGENT] Waiting for threads to stop...")
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=3)
        if self._batch_thread:
            self._batch_thread.join(timeout=3)

        print("[AGENT] Agent stopped cleanly.")

    def stop(self):
        """Stop the agent."""
        self._running = False

    def _log_connection_state(self, new_state: str):
        """Phase 8.1: Log connection state transitions (once per transition, not spammy)."""
        now = time.time()
        # Only log if state changed and at least 5 seconds since last log
        if new_state != self._connection_state and (now - self._last_connection_log_time) >= 5.0:
            print(f"[CONNECTION] State: {self._connection_state} → {new_state}")
            self._connection_state = new_state
            self._last_connection_log_time = now

    def _retry_with_backoff(self, func, operation_name: str):
        """
        Phase 8.1: Exponential backoff retry logic.
        
        Args:
            func: Function to call (no args).
            operation_name: Name of operation for logging.
        
        Returns:
            Result of func() if successful.
        
        Raises:
            Exception: On non-retryable errors (401/403) or max retries exceeded.
        """
        delay = self.retry_initial
        max_attempts = 10  # Reasonable limit
        attempt = 0
        
        while attempt < max_attempts:
            try:
                result = func()
                # Success - log reconnection if was disconnected
                if self._connection_state in ["DISCONNECTED", "RECONNECTED"]:
                    self._log_connection_state("CONNECTED")
                return result
            except Exception as e:
                error_msg = str(e).lower()
                
                # Phase 8.1: Do NOT retry on 401/403 (auth errors)
                if "401" in error_msg or "403" in error_msg:
                    print(f"[{operation_name}] Auth error (not retrying): {e}")
                    raise
                
                # Phase 8.1: Retry on connection errors or 5xx
                retryable = (
                    "connection" in error_msg or
                    "500" in error_msg or
                    "502" in error_msg or
                    "503" in error_msg or
                    "504" in error_msg or
                    "timeout" in error_msg
                )
                
                if not retryable:
                    # Non-retryable error
                    print(f"[{operation_name}] Non-retryable error: {e}")
                    raise
                
                # Phase 8.1: Log disconnection state
                if self._connection_state == "CONNECTED":
                    self._log_connection_state("DISCONNECTED")
                
                attempt += 1
                if attempt < max_attempts:
                    print(f"[{operation_name}] Retry {attempt}/{max_attempts} after {delay}s: {e}")
                    time.sleep(delay)
                    delay = min(delay * 2, self.retry_max)  # Exponential backoff with max
                else:
                    print(f"[{operation_name}] Max retries exceeded: {e}")
                    raise
        
        raise Exception(f"{operation_name} failed after {max_attempts} attempts")

    def _heartbeat_loop(self):
        """Background loop for sending heartbeats with retry."""
        while self._running:
            try:
                # Phase 8.1: Retry with exponential backoff
                self._retry_with_backoff(
                    lambda: self.client.send_heartbeat(self.host_id, self.host_name),
                    "HEARTBEAT"
                )
                # Log success only occasionally to avoid spam
                # (detailed logging happens in retry logic)
            except Exception as e:
                # Non-retryable error (e.g., auth) - log and continue loop
                # Will retry on next interval
                pass

            # Sleep until next heartbeat
            if self._running:
                time.sleep(self.heartbeat_interval)

    def _batch_loop(self):
        """Background loop for sending batched events with retry."""
        while self._running:
            try:
                # Generate demo events (MVP simulation)
                events = []
                for _ in range(1, 4):  # Generate 1-3 events per batch
                    event = normalize_demo_event(self.host_id)
                    events.append(event)
                    self._event_buffer.append(event)

                # Send batch if we have events
                if events:
                    # Phase 8.1: Retry with exponential backoff
                    response = self._retry_with_backoff(
                        lambda: self.client.send_batch(self.host_id, events),
                        "BATCH"
                    )
                    accepted = response.get("accepted", 0)
                    incident_ids = response.get("incident_ids", [])
                    print(f"[BATCH] Sent {accepted} events, {len(incident_ids)} incidents created/updated")
                    self._event_buffer.clear()
            except Exception as e:
                # Non-retryable error (e.g., auth) - log and continue loop
                # Will retry on next interval
                pass

            # Sleep until next batch
            if self._running:
                time.sleep(self.batch_interval)
