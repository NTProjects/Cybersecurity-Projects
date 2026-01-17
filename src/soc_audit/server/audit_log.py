"""Immutable Audit Log for SOC Audit Server.

Phase 10.2: Enterprise Audit Logging
- Immutable audit log (who, what, when, where)
- Stored separately from operational data
- Tamper-evident (hash chaining)
- Chain of custody for compliance
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any


class AuditLogger:
    """
    Immutable audit logger with hash chaining for tamper detection.
    
    Phase 10.2: Enterprise audit logging with chain of custody.
    """
    
    def __init__(self, db_path: str | Path):
        """
        Initialize audit logger.
        
        Args:
            db_path: Path to SQLite database for audit log.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        
        # Initialize schema
        self._init_schema()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn
    
    def _init_schema(self) -> None:
        """Initialize audit log database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id TEXT,
                role TEXT NOT NULL,
                operation TEXT NOT NULL,
                endpoint TEXT,
                object_type TEXT,
                object_id TEXT,
                action TEXT NOT NULL,
                result TEXT NOT NULL,
                details TEXT,
                previous_hash TEXT,
                entry_hash TEXT NOT NULL
            )
        """
        )
        
        # Create indexes
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_entry_hash ON audit_log(entry_hash)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_user_role ON audit_log(user_id, role)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_operation ON audit_log(operation)"
        )
        
        conn.commit()
    
    def log(
        self,
        user_id: str | None,
        role: str,
        operation: str,
        action: str,
        result: str,
        endpoint: str | None = None,
        object_type: str | None = None,
        object_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> int:
        """
        Log an audit event with hash chaining.
        
        Args:
            user_id: User identifier (API key hash or username).
            role: User role (agent, analyst, admin).
            operation: Operation name (read_alerts, suppress_alert, etc.).
            action: Action type (read, create, update, delete, suppress, etc.).
            result: Result (success, denied, error).
            endpoint: API endpoint path.
            object_type: Type of object (alert, incident, host).
            object_id: Object identifier.
            details: Additional context as dictionary.
        
        Returns:
            Audit log entry ID.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Get previous entry hash for chaining
        cursor.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        )
        row = cursor.fetchone()
        previous_hash = row["entry_hash"] if row else None
        
        # Create entry data
        timestamp = datetime.utcnow()
        details_json = json.dumps(details) if details else None
        
        entry_data = {
            "timestamp": timestamp.isoformat(),
            "user_id": user_id,
            "role": role,
            "operation": operation,
            "endpoint": endpoint,
            "object_type": object_type,
            "object_id": object_id,
            "action": action,
            "result": result,
            "details": details_json,
            "previous_hash": previous_hash,
        }
        
        # Calculate hash of this entry (tamper-evident)
        entry_hash = self._calculate_hash(entry_data, previous_hash)
        
        # Insert audit log entry
        cursor.execute(
            """
            INSERT INTO audit_log (
                timestamp, user_id, role, operation, endpoint,
                object_type, object_id, action, result, details,
                previous_hash, entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                timestamp.isoformat(),
                user_id,
                role,
                operation,
                endpoint,
                object_type,
                object_id,
                action,
                result,
                details_json,
                previous_hash,
                entry_hash,
            ),
        )
        
        conn.commit()
        return cursor.lastrowid
    
    def _calculate_hash(self, entry_data: dict[str, Any], previous_hash: str | None) -> str:
        """
        Calculate SHA-256 hash of audit log entry.
        
        Includes previous_hash in calculation for chain integrity.
        """
        # Create hashable string from entry data
        hash_data = {
            "timestamp": entry_data["timestamp"],
            "user_id": entry_data.get("user_id") or "",
            "role": entry_data["role"],
            "operation": entry_data["operation"],
            "endpoint": entry_data.get("endpoint") or "",
            "object_type": entry_data.get("object_type") or "",
            "object_id": entry_data.get("object_id") or "",
            "action": entry_data["action"],
            "result": entry_data["result"],
            "details": entry_data.get("details") or "",
            "previous_hash": previous_hash or "",
        }
        
        hash_string = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_string.encode("utf-8")).hexdigest()
    
    def verify_chain(self) -> tuple[bool, list[str]]:
        """
        Verify integrity of audit log chain.
        
        Returns:
            Tuple of (is_valid, list_of_errors).
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        errors = []
        
        cursor.execute("SELECT * FROM audit_log ORDER BY id")
        rows = cursor.fetchall()
        
        previous_hash = None
        for row in rows:
            # Recalculate hash
            entry_data = {
                "timestamp": row["timestamp"] or "",
                "user_id": row["user_id"] or "",
                "role": row["role"],
                "operation": row["operation"],
                "endpoint": row["endpoint"] or "",
                "object_type": row["object_type"] or "",
                "object_id": row["object_id"] or "",
                "action": row["action"],
                "result": row["result"],
                "details": row["details"] or "",
                "previous_hash": previous_hash or "",
            }
            
            expected_hash = self._calculate_hash(entry_data, previous_hash)
            
            # Check hash matches
            if row["entry_hash"] != expected_hash:
                errors.append(
                    f"Entry {row['id']}: Hash mismatch (expected {expected_hash[:16]}..., got {row['entry_hash'][:16]}...)"
                )
            
            # Check previous_hash chain
            if row["previous_hash"] != previous_hash:
                errors.append(
                    f"Entry {row['id']}: Previous hash chain broken (expected {previous_hash[:16] if previous_hash else 'None'}..., got {row['previous_hash'][:16] if row['previous_hash'] else 'None'}...)"
                )
            
            previous_hash = row["entry_hash"]
        
        return len(errors) == 0, errors
    
    def query(
        self,
        user_id: str | None = None,
        role: str | None = None,
        operation: str | None = None,
        object_type: str | None = None,
        object_id: str | None = None,
        action: str | None = None,
        result: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """
        Query audit log entries with filters.
        
        Returns:
            List of audit log entries as dictionaries.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        if role:
            query += " AND role = ?"
            params.append(role)
        if operation:
            query += " AND operation = ?"
            params.append(operation)
        if object_type:
            query += " AND object_type = ?"
            params.append(object_type)
        if object_id:
            query += " AND object_id = ?"
            params.append(object_id)
        if action:
            query += " AND action = ?"
            params.append(action)
        if result:
            query += " AND result = ?"
            params.append(result)
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        entries = []
        for row in rows:
            entries.append({
                "id": row["id"],
                "timestamp": row["timestamp"],
                "user_id": row["user_id"],
                "role": row["role"],
                "operation": row["operation"],
                "endpoint": row["endpoint"],
                "object_type": row["object_type"],
                "object_id": row["object_id"],
                "action": row["action"],
                "result": row["result"],
                "details": json.loads(row["details"]) if row["details"] else None,
                "previous_hash": row["previous_hash"],
                "entry_hash": row["entry_hash"],
            })
        
        return entries
    
    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
