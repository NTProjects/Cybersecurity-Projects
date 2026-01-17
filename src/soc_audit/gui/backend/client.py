"""Backend client for REST polling and WebSocket streaming."""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
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
        self._last_host_poll_time: float = 0  # Performance: Track host polling separately
        self._seen_alert_ids: set[str] = set()  # Deduplication
        self._last_seen_alert_timestamp: datetime | None = None  # Performance: Track latest alert timestamp for incremental updates
        
        # Status tracking
        self.status = "disconnected"  # disconnected, polling, connected, error
        self.last_error: str | None = None
        self.backend_role: str | None = None  # Phase 6.2: Role from backend
        
        # Phase 8.2: Host status cache
        self._host_status_cache: dict[str, str] = {}  # host_id -> "ONLINE" | "OFFLINE" | "UNKNOWN"
        self._host_last_seen_cache: dict[str, str] = {}  # host_id -> last_seen_ts (ISO string)
        
        # Phase 9.4: Host availability tracking
        self.hosts_ready = False
        self.hosts_cache: list[dict[str, Any]] = []  # Cached host list

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
                    # Phase 6.2: Look up role from config based on API key
                    if self.api_key and not self.backend_role:
                        try:
                            from soc_audit.server.auth import get_role_from_api_key
                            from soc_audit.core.config import load_config
                            
                            # Load config to get auth config
                            config = load_config()
                            backend_config = config.get("backend", {})
                            auth_config = backend_config.get("auth", {})
                            
                            # Look up role from API key
                            role = get_role_from_api_key(self.api_key, auth_config)
                            if role:
                                self.backend_role = role
                            else:
                                # Fallback: if key works but not in config, default to analyst
                                self.backend_role = "analyst"
                        except Exception:
                            # If lookup fails, default to analyst for backward compatibility
                            self.backend_role = "analyst"
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
        response = self._make_request("/api/v1/alerts?limit=10")
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

        Tolerant to multiple response shapes:
        - {"ok": true, "hosts": [...]}  (canonical)
        - {"hosts": [...]}              (partial)
        - [...]                         (list-only, legacy)

        Returns:
            List of host dicts with host_id, host_name, first_seen_ts, last_seen_ts, meta.
            Returns empty list on error.
        """
        response = self._make_request("/api/v1/hosts")
        
        # Handle empty/None response (silent - not an error during normal polling)
        if not response:
            return []
        
        # Handle list-only response (legacy)
        if isinstance(response, list):
            hosts = response
        # Handle dict response
        elif isinstance(response, dict):
            # Try canonical shape: {"ok": true, "hosts": [...]}
            if "hosts" in response:
                hosts = response.get("hosts", [])
                if not isinstance(hosts, list):
                    # Only log actual errors (unexpected shapes)
                    print(f"[GUI] get_hosts(): unexpected response shape: hosts field is not a list")
                    return []
            # Try legacy partial: just check if it's a dict with no "hosts" key
            else:
                # Only log actual errors (unexpected shapes)
                print(f"[GUI] get_hosts(): unexpected response shape: dict missing 'hosts' key, keys: {list(response.keys())}")
                return []
        else:
            # Only log actual errors (unexpected shapes)
            print(f"[GUI] get_hosts(): unexpected response shape: {type(response)}")
            return []
        
        # Validate hosts list contents
        if not isinstance(hosts, list):
            # Only log actual errors
            print("[GUI] get_hosts(): hosts is not a list after parsing")
            return []
        
        # Phase 8.2: Update host status cache on successful get_hosts()
        self._update_host_status_cache(hosts)
        
        # Phase 9.4: Update hosts cache and availability flag
        was_empty = not self.hosts_cache
        self.hosts_cache = hosts
        if hosts and not self.hosts_ready:
            self.hosts_ready = True
        
        return hosts
    
    def has_hosts(self) -> bool:
        """
        Phase 9.4: Check if hosts are available.
        
        Returns:
            True if hosts have been successfully fetched and cache is non-empty.
        """
        return self.hosts_ready and bool(self.hosts_cache)
    
    def _update_host_status_cache(self, hosts: list[dict[str, Any]]) -> None:
        """
        Phase 8.2: Update host status cache from hosts list.
        
        Args:
            hosts: List of host dicts from backend.
        """
        now = datetime.now(timezone.utc)
        heartbeat_interval = 10  # Default, matching server default
        
        for host in hosts:
            host_id = host.get("host_id")
            if not host_id:
                continue
            
            last_seen_ts = host.get("last_seen_ts")
            self._host_last_seen_cache[host_id] = last_seen_ts or ""
            
            # Calculate status (ONLINE if last_seen_ts within 2 × heartbeat_interval)
            status = "UNKNOWN"
            if last_seen_ts:
                try:
                    last_seen = datetime.fromisoformat(last_seen_ts.replace("Z", "+00:00"))
                    if not last_seen.tzinfo:
                        last_seen = last_seen.replace(tzinfo=timezone.utc)
                    
                    elapsed = (now - last_seen).total_seconds()
                    threshold = 2 * heartbeat_interval
                    status = "ONLINE" if elapsed <= threshold else "OFFLINE"
                except Exception:
                    status = "UNKNOWN"
            
            self._host_status_cache[host_id] = status
    
    def get_host_status(self, host_id: str) -> str:
        """
        Phase 8.2: Get host status from cache.
        
        Args:
            host_id: Host identifier.
        
        Returns:
            "ONLINE", "OFFLINE", or "UNKNOWN".
        """
        return self._host_status_cache.get(host_id, "UNKNOWN")
    
    def get_host_last_seen(self, host_id: str) -> str | None:
        """
        Phase 8.2: Get host last_seen timestamp from cache.
        
        Args:
            host_id: Host identifier.
        
        Returns:
            ISO timestamp string, or None if unknown.
        """
        return self._host_last_seen_cache.get(host_id)
    
    def get_incident_metrics(self) -> dict[str, Any] | None:
        """
        Phase 9.2: Get incident lifecycle metrics from backend.
        
        Returns:
            Dict with mttr_seconds, resolved_count, open_count, aging_buckets.
            Returns None on error.
        """
        response = self._make_request("/api/v1/incidents/metrics")
        if not response or not isinstance(response, dict):
            return None
        return response
    
    def get_incident_report(self) -> dict[str, Any] | None:
        """
        Phase 9.3: Get incident report from backend.
        
        Returns:
            Dict with incident report data.
            Returns None on error.
        """
        response = self._make_request("/api/v1/reports/incidents")
        if not response or not isinstance(response, dict):
            return None
        return response
    
    def get_host_report(self) -> dict[str, Any] | None:
        """
        Phase 9.3: Get host report from backend.
        
        Returns:
            Dict with host report data.
            Returns None on error.
        """
        response = self._make_request("/api/v1/reports/hosts")
        if not response or not isinstance(response, dict):
            return None
        return response

    def _poll_loop(self) -> None:
        """Background thread loop for REST polling."""
        self._polling = True
        self.status = "polling"
        
        if self.on_status:
            self.on_status("polling", "Backend polling started")
        
        consecutive_errors = 0
        max_consecutive_errors = 5
        
        while self._polling:
            try:
                # Only poll if authenticated (have API key)
                if not self.api_key:
                    # Wait longer if not authenticated
                    time.sleep(self.poll_interval_seconds * 2)
                    continue
                
                # Poll alerts
                try:
                    alerts = self.poll_alerts()
                    for alert in alerts:
                        # Deduplicate by alert_id
                        if alert.id not in self._seen_alert_ids:
                            self._seen_alert_ids.add(alert.id)
                            if self.on_alert:
                                try:
                                    self.on_alert(alert)
                                except Exception as callback_error:
                                    # Log but don't crash on callback errors
                                    print(f"[GUI] Error in alert callback: {callback_error}")
                except Exception as alert_error:
                    print(f"[GUI] Error polling alerts: {alert_error}")
                
                # Poll incidents
                try:
                    incidents = self.poll_incidents()
                    for incident in incidents:
                        if self.on_incident:
                            try:
                                self.on_incident(incident)
                            except Exception as callback_error:
                                print(f"[GUI] Error in incident callback: {callback_error}")
                except Exception as incident_error:
                    print(f"[GUI] Error polling incidents: {incident_error}")
                
                # Phase 8.2: Poll hosts to update status cache (only if authenticated)
                # Performance: Throttle host polling - only poll every 5th cycle to reduce overhead
                if self.api_key and self.backend_role in ["analyst", "admin"]:
                    # Use _last_poll_time to track host polling frequency
                    time_since_poll = time.time() - getattr(self, "_last_host_poll_time", 0)
                    if time_since_poll > 25.0:  # Poll hosts every 25 seconds (5 cycles at 5s interval)
                        try:
                            self.get_hosts()  # Updates cache internally
                            self._last_host_poll_time = time.time()
                        except Exception as host_error:
                            # Non-critical, continue polling
                            pass
                
                self._last_poll_time = time.time()
                self.last_error = None
                consecutive_errors = 0  # Reset error counter on success
                
                if self.status != "connected":  # Don't override WebSocket status
                    self.status = "polling"
                
            except Exception as e:
                consecutive_errors += 1
                self.status = "error"
                self.last_error = str(e)
                
                # Only log errors occasionally to avoid spam
                if consecutive_errors <= 1 or consecutive_errors % 10 == 0:
                    if self.on_status:
                        self.on_status("error", f"Backend polling error: {e}")
                    print(f"[GUI] Backend polling error ({consecutive_errors}): {e}")
                
                # Back off on repeated errors
                sleep_time = self.poll_interval_seconds
                if consecutive_errors > max_consecutive_errors:
                    sleep_time = min(self.poll_interval_seconds * 2, 30.0)  # Cap at 30s
                
                time.sleep(sleep_time)
                continue
            
            # Sleep until next poll
            time.sleep(self.poll_interval_seconds)
        
        self.status = "disconnected"
        # Phase 8.2: Clear host status cache on disconnect
        self._host_status_cache.clear()
        self._host_last_seen_cache.clear()
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
