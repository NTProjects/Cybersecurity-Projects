"""Server-side storage with multi-host support."""
from __future__ import annotations

import json
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any

from soc_audit.core.models import AlertEvent, Incident


class BackendStorage(ABC):
    """Abstract base class for backend storage."""

    @abstractmethod
    def init(self) -> None:
        """Initialize storage backend."""
        pass

    @abstractmethod
    def save_alert(self, alert_dict: dict[str, Any]) -> None:
        """Save alert from dict (from API schema)."""
        pass

    @abstractmethod
    def save_incident(self, incident_dict: dict[str, Any]) -> None:
        """Save incident from dict."""
        pass

    @abstractmethod
    def append_timeline(self, entry_dict: dict[str, Any]) -> None:
        """Append timeline entry from dict."""
        pass

    @abstractmethod
    def list_alerts(self, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """List alerts with optional filters."""
        pass

    @abstractmethod
    def list_incidents(self, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """List incidents with optional filters."""
        pass

    @abstractmethod
    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        """Get alert by ID."""
        pass

    @abstractmethod
    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        """Get incident by ID."""
        pass

    @abstractmethod
    def update_alert_ack(self, alert_id: str, acked: bool, acked_at: str | None = None) -> None:
        """Update alert acknowledgement status."""
        pass

    @abstractmethod
    def update_alert_suppressed(
        self, alert_id: str, suppressed: bool, suppressed_until: str | None = None
    ) -> None:
        """Update alert suppression status."""
        pass

    @abstractmethod
    def update_incident_status(
        self, incident_id: str, status: str | None = None, notes: str | None = None
    ) -> None:
        """Update incident status and/or notes."""
        pass

    @abstractmethod
    def add_incident_note(self, incident_id: str, note: str) -> None:
        """Add note to incident."""
        pass

    # -------- Phase 7: Host registry --------

    @abstractmethod
    def upsert_host(self, host_info: dict[str, Any]) -> None:
        """Create or update a host record."""
        pass

    @abstractmethod
    def update_heartbeat(self, host_id: str, ts: str | None = None) -> None:
        """Update last_seen timestamp for a host."""
        pass

    @abstractmethod
    def list_hosts(self) -> list[dict[str, Any]]:
        """List all known hosts."""
        pass

    @abstractmethod
    def get_host(self, host_id: str) -> dict[str, Any] | None:
        """Get host details by ID."""
        pass

    @abstractmethod
    def get_host_status(self, host_id: str, heartbeat_interval: int = 10) -> str:
        """
        Get host status (ONLINE or OFFLINE).
        
        Args:
            host_id: Host identifier.
            heartbeat_interval: Heartbeat interval in seconds (default 10).
                               Host is OFFLINE if last_seen_ts > 2 × heartbeat_interval ago.
        
        Returns:
            "ONLINE" or "OFFLINE".
        """
        pass

    @abstractmethod
    def get_incident_metrics(self) -> dict[str, Any]:
        """
        Phase 9.2: Get incident lifecycle metrics (MTTR, aging buckets).
        
        Returns:
            Dict with mttr_seconds, resolved_count, open_count, aging_buckets.
        """
        pass


class SQLiteBackendStorage(BackendStorage):
    """SQLite backend storage with multi-host support."""

    def __init__(self, db_path: str | Path):
        """Initialize SQLite backend storage."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def init(self) -> None:
        """Initialize database schema with multi-host support."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Alerts table (additive: host_id, host_name, received_ts, suppressed_until, notes)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                module TEXT NOT NULL,
                title TEXT NOT NULL,
                source TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                mitre_tactics_json TEXT,
                mitre_techniques_json TEXT,
                mitre_ids_json TEXT NOT NULL,
                rba_score INTEGER,
                rba_breakdown_json TEXT,
                entity_keys_json TEXT NOT NULL,
                acked INTEGER NOT NULL DEFAULT 0,
                suppressed INTEGER NOT NULL DEFAULT 0,
                incident_id TEXT,
                host_id TEXT NOT NULL,
                host_name TEXT,
                received_ts TEXT NOT NULL,
                suppressed_until TEXT,
                notes TEXT
            )
        """
        )

        # Incidents table (additive: host_id)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                created_ts TEXT NOT NULL,
                updated_ts TEXT NOT NULL,
                severity_max TEXT NOT NULL,
                rba_max INTEGER,
                entity_summary_json TEXT NOT NULL,
                alert_count INTEGER NOT NULL DEFAULT 0,
                notes TEXT,
                host_id TEXT NOT NULL
            )
        """
        )

        # Timeline table (additive: host_id)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                message TEXT NOT NULL,
                level TEXT NOT NULL,
                source TEXT NOT NULL,
                module TEXT NOT NULL,
                alert_id TEXT,
                incident_id TEXT,
                host_id TEXT
            )
        """
        )

        # Hosts table (Phase 7: multi-host federation)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                host_id TEXT PRIMARY KEY,
                host_name TEXT,
                first_seen_ts TEXT NOT NULL,
                last_seen_ts TEXT NOT NULL,
                meta_json TEXT
            )
            """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen_ts)"
        )

        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_host ON incidents(host_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON timeline(timestamp)")

        conn.commit()

    def save_alert(self, alert_dict: dict[str, Any]) -> None:
        """Save alert from dict."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Ensure required fields
        if "host_id" not in alert_dict:
            raise ValueError("host_id is required")

        if "received_ts" not in alert_dict:
            alert_dict["received_ts"] = datetime.utcnow().isoformat()

        cursor.execute(
            """
            INSERT OR REPLACE INTO alerts
            (id, timestamp, severity, module, title, source, evidence_json,
             mitre_tactics_json, mitre_techniques_json, mitre_ids_json,
             rba_score, rba_breakdown_json, entity_keys_json,
             acked, suppressed, incident_id, host_id, host_name, received_ts,
             suppressed_until, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                alert_dict["id"],
                alert_dict["timestamp"],
                alert_dict["severity"],
                alert_dict["module"],
                alert_dict["title"],
                alert_dict["source"],
                json.dumps(alert_dict.get("evidence", {})),
                json.dumps(alert_dict.get("mitre_tactics", [])),
                json.dumps(alert_dict.get("mitre_techniques", [])),
                json.dumps(alert_dict.get("mitre_ids", [])),
                alert_dict.get("rba_score"),
                json.dumps(alert_dict.get("rba_breakdown")) if alert_dict.get("rba_breakdown") else None,
                json.dumps(alert_dict.get("entity_keys", {})),
                1 if alert_dict.get("acked", False) else 0,
                1 if alert_dict.get("suppressed", False) else 0,
                alert_dict.get("incident_id"),
                alert_dict["host_id"],
                alert_dict.get("host_name"),
                alert_dict["received_ts"],
                alert_dict.get("suppressed_until"),
                alert_dict.get("notes"),
            ),
        )

        conn.commit()

    def save_incident(self, incident_dict: dict[str, Any]) -> None:
        """Save incident from dict."""
        conn = self._get_connection()
        cursor = conn.cursor()

        if "host_id" not in incident_dict:
            raise ValueError("host_id is required for incidents")

        cursor.execute(
            """
            INSERT OR REPLACE INTO incidents
            (id, title, status, created_ts, updated_ts, severity_max, rba_max,
             entity_summary_json, alert_count, notes, host_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                incident_dict["id"],
                incident_dict["title"],
                incident_dict["status"],
                incident_dict["created_ts"],
                incident_dict["updated_ts"],
                incident_dict["severity_max"],
                incident_dict.get("rba_max"),
                json.dumps(incident_dict.get("entity_summary", {})),
                incident_dict.get("alert_count", 0),
                incident_dict.get("notes"),
                incident_dict["host_id"],
            ),
        )

        conn.commit()

    def append_timeline(self, entry_dict: dict[str, Any]) -> None:
        """Append timeline entry from dict."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO timeline (timestamp, message, level, source, module, alert_id, incident_id, host_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                entry_dict.get("timestamp", datetime.utcnow().isoformat()),
                entry_dict["message"],
                entry_dict["level"],
                entry_dict["source"],
                entry_dict["module"],
                entry_dict.get("alert_id"),
                entry_dict.get("incident_id"),
                entry_dict.get("host_id"),
            ),
        )

        conn.commit()

    # -------- Phase 7: Host registry --------

    def upsert_host(self, host_info: dict[str, Any]) -> None:
        """Create or update a host record."""
        conn = self._get_connection()
        cursor = conn.cursor()

        host_id = host_info["host_id"]
        host_name = host_info.get("host_name")
        now = datetime.utcnow().isoformat()

        # Load existing host (if any) to preserve first_seen_ts / meta
        cursor.execute(
            "SELECT host_id, host_name, first_seen_ts, last_seen_ts, meta_json FROM hosts WHERE host_id = ?",
            (host_id,),
        )
        row = cursor.fetchone()

        if row:
            first_seen_ts = row["first_seen_ts"]
            meta = json.loads(row["meta_json"]) if row["meta_json"] else {}
            # Merge metadata
            meta.update(host_info.get("meta", {}))
        else:
            first_seen_ts = now
            meta = host_info.get("meta", {})

        cursor.execute(
            """
            INSERT OR REPLACE INTO hosts
            (host_id, host_name, first_seen_ts, last_seen_ts, meta_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (host_id, host_name, first_seen_ts, now, json.dumps(meta) if meta else None),
        )
        conn.commit()

    def update_heartbeat(self, host_id: str, ts: str | None = None) -> None:
        """Update last_seen timestamp for a host."""
        conn = self._get_connection()
        cursor = conn.cursor()

        now = ts or datetime.utcnow().isoformat()

        # Ensure host exists; if not, create minimal record
        cursor.execute(
            "SELECT host_id, host_name, first_seen_ts, meta_json FROM hosts WHERE host_id = ?",
            (host_id,),
        )
        row = cursor.fetchone()
        if row:
            first_seen_ts = row["first_seen_ts"]
            host_name = row["host_name"]
            meta_json = row["meta_json"]
        else:
            first_seen_ts = now
            host_name = None
            meta_json = None

        cursor.execute(
            """
            INSERT OR REPLACE INTO hosts
            (host_id, host_name, first_seen_ts, last_seen_ts, meta_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (host_id, host_name, first_seen_ts, now, meta_json),
        )
        conn.commit()

    def list_hosts(self) -> list[dict[str, Any]]:
        """List all known hosts, sorted by last_seen_ts DESC."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT host_id, host_name, first_seen_ts, last_seen_ts, meta_json FROM hosts ORDER BY last_seen_ts DESC"
        )
        rows = cursor.fetchall()
        hosts: list[dict[str, Any]] = []
        for row in rows:
            meta = json.loads(row["meta_json"]) if row["meta_json"] else {}
            hosts.append(
                {
                    "host_id": row["host_id"],
                    "host_name": row["host_name"],
                    "first_seen_ts": row["first_seen_ts"],
                    "last_seen_ts": row["last_seen_ts"],
                    "meta": meta,
                }
            )
        return hosts

    def get_host(self, host_id: str) -> dict[str, Any] | None:
        """Get host details by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT host_id, host_name, first_seen_ts, last_seen_ts, meta_json FROM hosts WHERE host_id = ?",
            (host_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        meta = json.loads(row["meta_json"]) if row["meta_json"] else {}
        return {
            "host_id": row["host_id"],
            "host_name": row["host_name"],
            "first_seen_ts": row["first_seen_ts"],
            "last_seen_ts": row["last_seen_ts"],
            "meta": meta,
        }

    def list_alerts(self, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """List alerts with optional filters."""
        conn = self._get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []

        if filters:
            if "host_id" in filters:
                query += " AND host_id = ?"
                params.append(filters["host_id"])
            if "severity" in filters:
                query += " AND severity = ?"
                params.append(filters["severity"])
            if "rba_min" in filters:
                query += " AND rba_score >= ?"
                params.append(filters["rba_min"])
            if "rba_max" in filters:
                query += " AND rba_score <= ?"
                params.append(filters["rba_max"])
            if "incident_id" in filters:
                query += " AND incident_id = ?"
                params.append(filters["incident_id"])
            if "acked" in filters:
                query += " AND acked = ?"
                params.append(1 if filters["acked"] else 0)
            if "suppressed" in filters:
                query += " AND suppressed = ?"
                params.append(1 if filters["suppressed"] else 0)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(filters.get("limit", 500) if filters else 500)

        cursor.execute(query, params)

        alerts = []
        for row in cursor.fetchall():
            try:
                alert_dict = {
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "severity": row["severity"],
                    "module": row["module"],
                    "title": row["title"],
                    "source": row["source"],
                    "evidence": json.loads(row["evidence_json"]),
                    "mitre_ids": json.loads(row["mitre_ids_json"]),
                    "rba_score": row["rba_score"],
                    "entity_keys": json.loads(row["entity_keys_json"]),
                    "acked": bool(row["acked"]),
                    "suppressed": bool(row["suppressed"]),
                    "incident_id": row["incident_id"],
                    "host_id": row["host_id"],
                    "host_name": row["host_name"],
                    "received_ts": row["received_ts"],
                    "suppressed_until": row["suppressed_until"],
                    "notes": row["notes"],
                }
                alerts.append(alert_dict)
            except Exception:
                continue

        return alerts

    def list_incidents(self, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """List incidents with optional filters."""
        conn = self._get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM incidents WHERE 1=1"
        params: list[Any] = []

        if filters:
            if "host_id" in filters:
                query += " AND host_id = ?"
                params.append(filters["host_id"])
            if "status" in filters:
                query += " AND status = ?"
                params.append(filters["status"])

        query += " ORDER BY updated_ts DESC"

        cursor.execute(query, params)

        incidents = []
        for row in cursor.fetchall():
            try:
                incident_dict = {
                    "id": row["id"],
                    "title": row["title"],
                    "status": row["status"],
                    "created_ts": row["created_ts"],
                    "updated_ts": row["updated_ts"],
                    "severity_max": row["severity_max"],
                    "rba_max": row["rba_max"],
                    "entity_summary": json.loads(row["entity_summary_json"]),
                    "alert_count": row["alert_count"],
                    "notes": row["notes"],
                    "host_id": row["host_id"],
                }
                incidents.append(incident_dict)
            except Exception:
                continue

        return incidents

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        """Get alert by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()

        if not row:
            return None

        try:
            return {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "severity": row["severity"],
                "module": row["module"],
                "title": row["title"],
                "source": row["source"],
                "evidence": json.loads(row["evidence_json"]),
                "mitre_ids": json.loads(row["mitre_ids_json"]),
                "rba_score": row["rba_score"],
                "entity_keys": json.loads(row["entity_keys_json"]),
                "acked": bool(row["acked"]),
                "suppressed": bool(row["suppressed"]),
                "incident_id": row["incident_id"],
                "host_id": row["host_id"],
                "host_name": row["host_name"],
                "received_ts": row["received_ts"],
                "suppressed_until": row["suppressed_until"],
                "notes": row["notes"],
            }
        except Exception:
            return None

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        """Get incident by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = cursor.fetchone()

        if not row:
            return None

        try:
            return {
                "id": row["id"],
                "title": row["title"],
                "status": row["status"],
                "created_ts": row["created_ts"],
                "updated_ts": row["updated_ts"],
                "severity_max": row["severity_max"],
                "rba_max": row["rba_max"],
                "entity_summary": json.loads(row["entity_summary_json"]),
                "alert_count": row["alert_count"],
                "notes": row["notes"],
                "host_id": row["host_id"],
            }
        except Exception:
            return None

    def update_alert_ack(self, alert_id: str, acked: bool, acked_at: str | None = None) -> None:
        """Update alert acknowledgement status."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE alerts SET acked = ? WHERE id = ?",
            (1 if acked else 0, alert_id),
        )

        conn.commit()

    def update_alert_suppressed(
        self, alert_id: str, suppressed: bool, suppressed_until: str | None = None
    ) -> None:
        """Update alert suppression status."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE alerts SET suppressed = ?, suppressed_until = ? WHERE id = ?",
            (1 if suppressed else 0, suppressed_until, alert_id),
        )

        conn.commit()

    def update_incident_status(
        self, incident_id: str, status: str | None = None, notes: str | None = None
    ) -> None:
        """Update incident status and/or notes."""
        conn = self._get_connection()
        cursor = conn.cursor()

        updates = []
        params: list[Any] = []

        if status is not None:
            updates.append("status = ?")
            params.append(status)

        if notes is not None:
            updates.append("notes = ?")
            params.append(notes)

        updates.append("updated_ts = ?")
        params.append(datetime.utcnow().isoformat())

        params.append(incident_id)

        query = f"UPDATE incidents SET {', '.join(updates)} WHERE id = ?"
        cursor.execute(query, params)

        conn.commit()

    def add_incident_note(self, incident_id: str, note: str) -> None:
        """Add note to incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise ValueError(f"Incident not found: {incident_id}")

        existing_notes = incident.get("notes") or ""
        new_notes = f"{existing_notes}\n[{datetime.utcnow().isoformat()}] {note}".strip()

        self.update_incident_status(incident_id, notes=new_notes)

    def get_incident_metrics(self) -> dict[str, Any]:
        """
        Phase 9.2: Get incident lifecycle metrics (MTTR, aging buckets).
        
        Returns:
            Dict with:
            - mttr_seconds: float | None (MTTR in seconds, None if no closed incidents)
            - resolved_count: int
            - open_count: int
            - aging_buckets: dict with "<1h", "1-4h", "4-24h", ">24h" counts
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Get all incidents
        cursor.execute("SELECT status, created_ts, updated_ts FROM incidents")
        rows = cursor.fetchall()
        
        now = datetime.utcnow()
        resolved_count = 0
        open_count = 0
        total_resolution_time = 0.0
        aging_buckets = {"<1h": 0, "1-4h": 0, "4-24h": 0, ">24h": 0}
        
        for row in rows:
            status = row["status"]
            created_ts = row["created_ts"]
            updated_ts = row["updated_ts"]
            
            if status == "closed":
                resolved_count += 1
                try:
                    created_dt = datetime.fromisoformat(created_ts.replace("Z", "+00:00"))
                    updated_dt = datetime.fromisoformat(updated_ts.replace("Z", "+00:00"))
                    if created_dt.tzinfo:
                        now_with_tz = now.replace(tzinfo=created_dt.tzinfo)
                        updated_dt = updated_dt.replace(tzinfo=created_dt.tzinfo) if not updated_dt.tzinfo else updated_dt
                    else:
                        now_with_tz = now
                    
                    resolution_time = (updated_dt - created_dt).total_seconds()
                    total_resolution_time += resolution_time
                except Exception:
                    pass
            elif status == "open":
                open_count += 1
                try:
                    created_dt = datetime.fromisoformat(created_ts.replace("Z", "+00:00"))
                    if created_dt.tzinfo:
                        now_with_tz = now.replace(tzinfo=created_dt.tzinfo)
                    else:
                        now_with_tz = now
                    
                    age_seconds = (now_with_tz - created_dt).total_seconds()
                    
                    if age_seconds < 3600:  # < 1 hour
                        aging_buckets["<1h"] += 1
                    elif age_seconds < 4 * 3600:  # 1-4 hours
                        aging_buckets["1-4h"] += 1
                    elif age_seconds < 24 * 3600:  # 4-24 hours
                        aging_buckets["4-24h"] += 1
                    else:  # > 24 hours
                        aging_buckets[">24h"] += 1
                except Exception:
                    pass
        
        # Calculate MTTR (only from closed incidents)
        mttr_seconds = total_resolution_time / resolved_count if resolved_count > 0 else None
        
        return {
            "mttr_seconds": mttr_seconds,
            "resolved_count": resolved_count,
            "open_count": open_count,
            "aging_buckets": aging_buckets,
        }

    def get_host_status(self, host_id: str, heartbeat_interval: int = 10) -> str:
        """
        Get host status (ONLINE or OFFLINE).
        
        Phase 8.1: Status logic - ONLINE if now - last_seen_ts <= 2 × heartbeat_interval.
        
        Args:
            host_id: Host identifier.
            heartbeat_interval: Heartbeat interval in seconds (default 10).
        
        Returns:
            "ONLINE" or "OFFLINE".
        """
        host = self.get_host(host_id)
        if not host:
            return "OFFLINE"
        
        # Parse last_seen_ts
        try:
            last_seen_dt = datetime.fromisoformat(host["last_seen_ts"].replace("Z", "+00:00"))
        except Exception:
            return "OFFLINE"
        
        # Calculate time since last heartbeat
        now = datetime.utcnow()
        if last_seen_dt.tzinfo:
            now = now.replace(tzinfo=last_seen_dt.tzinfo)
        
        time_since_last = (now - last_seen_dt).total_seconds()
        threshold = 2 * heartbeat_interval
        
        return "ONLINE" if time_since_last <= threshold else "OFFLINE"
