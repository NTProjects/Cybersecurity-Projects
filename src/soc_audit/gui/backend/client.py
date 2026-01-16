"""Backend client for REST polling and WebSocket streaming."""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from typing import Any, Callable
from urllib import request
from urllib.error import URLError

from soc_audit.core.models import AlertEvent, Incident


class BackendClient:
    """
    Client for connecting to SOC Audit backend server.
    
    Supports REST polling and optional WebSocket streaming.
    Runs in background threads and communicates with GUI via queues.
    """

    def __init__(
        self,
        api_url: str,
        ws_url: str | None = None,
        api_key: str | None = None,
        poll_interval_seconds: float = 5.0,
        use_websocket: bool = True,
        on_alert: Callable[[AlertEvent], None] | None = None,
        on_incident: Callable[[Incident], None] | None = None,
        on_status: Callable[[str, str], None] | None = None,  # (status, message)
    ):
        """
        Initialize the backend client.

        Args:
            api_url: Base API URL (e.g., "http://127.0.0.1:8001").
            ws_url: WebSocket URL (e.g., "ws://127.0.0.1:8001/ws/stream").
            api_key: Optional API key for authentication.
            poll_interval_seconds: REST polling interval in seconds.
            use_websocket: Whether to attempt WebSocket connection.
            on_alert: Callback invoked when an alert is received.
            on_incident: Callback invoked when an incident is received.
            on_status: Callback for status updates (status, message).
        """
        self.api_url = api_url.rstrip("/")
        self.ws_url = ws_url
        self.api_key = api_key
        self.poll_interval_seconds = poll_interval_seconds
        self.use_websocket = use_websocket
        
        self.on_alert = on_alert
        self.on_incident = on_incident
        self.on_status = on_status
        
        self._polling = False
        self._poll_thread: threading.Thread | None = None
        self._ws_thread: threading.Thread | None = None
        self._ws_connected = False
        self._last_poll_time: float = 0
        self._seen_alert_ids: set[str] = set()  # Deduplication
        
        # Status tracking
        self.status = "disconnected"  # disconnected, polling, connected, error
        self.last_error: str | None = None
        self.backend_role: str | None = None  # Phase 6.2: Role from backend

    def build_base_url(self) -> str:
        """Build the base API URL."""
        return self.api_url

    def set_api_key(self, api_key: str | None) -> None:
        """Update API key (Phase 6.2: for session-based auth)."""
        self.api_key = api_key
        # Reset role when key changes
        self.backend_role = None
    
    def _make_request(
        self, endpoint: str, method: str = "GET", data: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        """
        Make an HTTP request to the backend API.

        Args:
            endpoint: API endpoint (e.g., "/api/v1/alerts").
            method: HTTP method (GET, POST, etc.).
            data: Optional request body data.

        Returns:
            Response JSON as dict, or None on error.
        """
        url = f"{self.api_url}{endpoint}"
        
        try:
            req_data = None
            headers = {"Content-Type": "application/json"}
            
            if self.api_key:
                headers["X-API-Key"] = self.api_key
            
            if data:
                req_data = json.dumps(data).encode("utf-8")
            
            http_req = request.Request(url, data=req_data, headers=headers, method=method)
            
            with request.urlopen(http_req, timeout=5) as response:
                if response.status == 200:
                    # Phase 6.2: Try to infer role from response headers or first successful request
                    if self.api_key and not self.backend_role:
                        # For MVP, we'll set role based on successful auth
                        # In production, backend could return role in header
                        # For now, default to analyst if key works
                        self.backend_role = "analyst"  # Default, can be overridden
                    return json.loads(response.read().decode("utf-8"))
                elif response.status == 401:
                    self.last_error = "Authentication failed"
                    self.backend_role = None
                    return None
                else:
                    self.last_error = f"HTTP {response.status}"
                    return None
                    
        except URLError as e:
            self.last_error = f"Connection error: {str(e)}"
            return None
        except Exception as e:
            self.last_error = f"Request error: {str(e)}"
            return None

    def poll_alerts(self) -> list[AlertEvent]:
        """
        Poll the backend for recent alerts.

        Returns:
            List of AlertEvent objects.
        """
        response = self._make_request("/api/v1/alerts?limit=500")
        if not response:
            return []
        
        alerts = []
        if isinstance(response, list):
            for alert_dict in response:
                try:
                    # Convert API response to AlertEvent
                    # API may include host_id, host_name, received_ts which we ignore for GUI
                    alert = AlertEvent(
                        id=alert_dict["id"],
                        timestamp=datetime.fromisoformat(alert_dict["timestamp"]),
                        severity=alert_dict["severity"],
                        module=alert_dict["module"],
                        title=alert_dict["title"],
                        source=alert_dict.get("source", "backend"),
                        evidence=alert_dict.get("evidence", {}),
                        mitre_ids=alert_dict.get("mitre_ids", []),
                        rba_score=alert_dict.get("rba_score"),
                        entity_keys=alert_dict.get("entity_keys", {}),
                        acked=alert_dict.get("acked", False),
                        suppressed=alert_dict.get("suppressed", False),
                        incident_id=alert_dict.get("incident_id"),
                    )
                    alerts.append(alert)
                except Exception:
                    continue
        
        return alerts

    def poll_incidents(self) -> list[Incident]:
        """
        Poll the backend for incidents.

        Returns:
            List of Incident objects.
        """
        response = self._make_request("/api/v1/incidents")
        if not response:
            return []
        
        incidents = []
        if isinstance(response, list):
            for incident_dict in response:
                try:
                    # Convert API response to Incident
                    # API may include host_id which Incident.from_dict ignores (not in model)
                    incident = Incident.from_dict(incident_dict)
                    incidents.append(incident)
                except Exception:
                    continue
        
        return incidents

    def ack_alert(self, alert_id: str, acked: bool) -> bool:
        """
        Acknowledge or unacknowledge an alert.

        Args:
            alert_id: Alert ID.
            acked: True to acknowledge, False to unacknowledge.

        Returns:
            True if successful, False otherwise.
        """
        response = self._make_request(
            f"/api/v1/alerts/{alert_id}/ack", method="POST", data={"acked": acked}
        )
        return response is not None

    def suppress_alert(self, alert_id: str, suppressed: bool) -> bool:
        """
        Suppress or unsuppress an alert.

        Args:
            alert_id: Alert ID.
            suppressed: True to suppress, False to unsuppress.

        Returns:
            True if successful, False otherwise.
        """
        response = self._make_request(
            f"/api/v1/alerts/{alert_id}/suppress",
            method="POST",
            data={"suppressed": suppressed},
        )
        return response is not None

    def close_incident(self, incident_id: str) -> bool:
        """
        Close an incident.

        Args:
            incident_id: Incident ID.

        Returns:
            True if successful, False otherwise.
        """
        response = self._make_request(
            f"/api/v1/incidents/{incident_id}/close", method="POST"
        )
        return response is not None

    def add_incident_note(self, incident_id: str, note: str) -> bool:
        """
        Add a note to an incident.

        Args:
            incident_id: Incident ID.
            note: Note text.

        Returns:
            True if successful, False otherwise.
        """
        response = self._make_request(
            f"/api/v1/incidents/{incident_id}/note",
            method="POST",
            data={"note": note},
        )
        return response is not None

    def get_hosts(self) -> list[dict[str, Any]]:
        """
        Get list of registered hosts from the backend.

        Returns:
            List of host dicts with host_id, host_name, first_seen_ts, last_seen_ts, meta.
            Returns empty list on error.
        """
        response = self._make_request("/api/v1/hosts")
        if not response or not isinstance(response, dict):
            return []
        
        hosts = response.get("hosts", [])
        if not isinstance(hosts, list):
            return []
        
        return hosts

    def _poll_loop(self) -> None:
        """Background thread loop for REST polling."""
        self._polling = True
        self.status = "polling"
        
        if self.on_status:
            self.on_status("polling", "Backend polling started")
        
        while self._polling:
            try:
                # Poll alerts
                alerts = self.poll_alerts()
                for alert in alerts:
                    # Deduplicate by alert_id
                    if alert.id not in self._seen_alert_ids:
                        self._seen_alert_ids.add(alert.id)
                        if self.on_alert:
                            self.on_alert(alert)
                
                # Poll incidents
                incidents = self.poll_incidents()
                for incident in incidents:
                    if self.on_incident:
                        self.on_incident(incident)
                
                self._last_poll_time = time.time()
                self.last_error = None
                
                if self.status != "connected":  # Don't override WebSocket status
                    self.status = "polling"
                
            except Exception as e:
                self.status = "error"
                self.last_error = str(e)
                if self.on_status:
                    self.on_status("error", f"Backend polling error: {e}")
            
            # Sleep until next poll
            time.sleep(self.poll_interval_seconds)
        
        self.status = "disconnected"
        if self.on_status:
            self.on_status("disconnected", "Backend polling stopped")

    def start_polling(self) -> None:
        """Start REST polling in a background thread."""
        if self._polling:
            return
        
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def stop_polling(self) -> None:
        """Stop REST polling."""
        self._polling = False
        if self._poll_thread:
            self._poll_thread.join(timeout=2.0)
            self._poll_thread = None

    def connect_websocket(self) -> None:
        """
        Connect to WebSocket stream (optional, falls back to polling if fails).
        
        Note: WebSocket implementation uses polling fallback for MVP.
        Full WebSocket support would require websocket-client library.
        """
        # For MVP, WebSocket is not implemented (would require additional dependency)
        # Fallback to REST polling is automatic
        if self.on_status:
            self.on_status("polling", "WebSocket not available, using REST polling")

    def disconnect_websocket(self) -> None:
        """Disconnect from WebSocket stream."""
        self._ws_connected = False

    def start(self) -> None:
        """Start backend client (polling and optionally WebSocket)."""
        self.start_polling()
        if self.use_websocket:
            self.connect_websocket()

    def stop(self) -> None:
        """Stop backend client (polling and WebSocket)."""
        self.stop_polling()
        self.disconnect_websocket()

    def is_connected(self) -> bool:
        """Check if backend is connected (polling or WebSocket)."""
        return self.status in ("polling", "connected")
