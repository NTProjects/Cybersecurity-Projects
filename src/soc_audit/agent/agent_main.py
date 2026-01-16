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

        # Initialize client
        self.client = AgentClient(self.server_url, self.api_key)

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

        # Wait for threads to finish
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=2)
        if self._batch_thread:
            self._batch_thread.join(timeout=2)

        print("[AGENT] Agent stopped.")

    def stop(self):
        """Stop the agent."""
        self._running = False

    def _heartbeat_loop(self):
        """Background loop for sending heartbeats."""
        while self._running:
            try:
                self.client.send_heartbeat(self.host_id, self.host_name)
                print(f"[HEARTBEAT] Sent heartbeat for {self.host_id}")
            except Exception as e:
                print(f"[HEARTBEAT] Failed: {e}")

            # Sleep until next heartbeat
            time.sleep(self.heartbeat_interval)

    def _batch_loop(self):
        """Background loop for sending batched events."""
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
                    response = self.client.send_batch(self.host_id, events)
                    accepted = response.get("accepted", 0)
                    incident_ids = response.get("incident_ids", [])
                    print(f"[BATCH] Sent {accepted} events, {len(incident_ids)} incidents created/updated")
                    self._event_buffer.clear()
            except Exception as e:
                print(f"[BATCH] Failed: {e}")

            # Sleep until next batch
            time.sleep(self.batch_interval)
