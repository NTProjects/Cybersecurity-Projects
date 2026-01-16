"""HTTP client for agent-to-server communication."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class AgentClient:
    """Client for communicating with SOC Audit Server."""

    def __init__(self, server_url: str, api_key: str):
        """
        Initialize the agent client.

        Args:
            server_url: Base URL of the SOC server (e.g., "http://127.0.0.1:8001").
            api_key: API key for authentication.
        """
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key

    def _make_request(
        self, method: str, path: str, data: dict[str, Any] | None = None
    ) -> tuple[int, dict[str, Any] | list[Any]]:
        """
        Make HTTP request to server.

        Args:
            method: HTTP method (GET, POST, etc.).
            path: API path (e.g., "/api/v1/heartbeat").
            data: Optional request body dict.

        Returns:
            Tuple of (status_code, response_data).

        Raises:
            Exception: On network errors or non-200 responses.
        """
        url = f"{self.server_url}{path}"
        headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
        }

        body = None
        if data:
            body = json.dumps(data).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                status = response.status
                try:
                    response_data = json.loads(response.read().decode("utf-8"))
                except Exception:
                    response_data = {}
                return status, response_data
        except urllib.error.HTTPError as e:
            status = e.code
            try:
                error_data = json.loads(e.read().decode("utf-8"))
            except Exception:
                error_data = {"error": str(e)}
            raise Exception(f"HTTP {status}: {error_data}")
        except urllib.error.URLError as e:
            raise Exception(f"Connection error: {e}")
        except Exception as e:
            raise Exception(f"Request failed: {e}")

    def send_heartbeat(self, host_id: str, host_name: str | None = None, meta: dict[str, Any] | None = None) -> bool:
        """
        Send heartbeat to server.

        Args:
            host_id: Host identifier.
            host_name: Optional host display name.
            meta: Optional metadata dict.

        Returns:
            True if successful.

        Raises:
            Exception: On failure.
        """
        payload = {
            "host_id": host_id,
            "host_name": host_name,
            "meta": meta or {},
        }

        status, response = self._make_request("POST", "/api/v1/heartbeat", payload)

        if status != 200:
            raise Exception(f"Heartbeat failed with status {status}: {response}")

        if isinstance(response, dict) and not response.get("ok"):
            raise Exception(f"Heartbeat returned not ok: {response}")

        return True

    def send_batch(self, host_id: str, events: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Send batch of events to server.

        Args:
            host_id: Host identifier.
            events: List of normalized event dicts.

        Returns:
            Response dict with accepted count, incident_ids, etc.

        Raises:
            Exception: On failure.
        """
        payload = {
            "host_id": host_id,
            "events": events,
        }

        status, response = self._make_request("POST", "/api/v1/ingest/batch", payload)

        if status != 200:
            raise Exception(f"Batch ingest failed with status {status}: {response}")

        if isinstance(response, dict) and not response.get("ok"):
            raise Exception(f"Batch ingest returned not ok: {response}")

        return response
