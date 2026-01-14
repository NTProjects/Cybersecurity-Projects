"""Timeline and incident export functionality.

This module provides functions to export timeline events and incidents
to JSON and text formats for reporting and analysis.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from soc_audit.core.storage import Storage


def export_timeline_json(storage: Storage, out_path: str | Path) -> None:
    """
    Export timeline events to JSON format.

    Args:
        storage: Storage backend to read from.
        out_path: Output file path.
    """
    # Load timeline entries (simplified - in production, add timeline loading to Storage)
    # For now, we'll export alerts and incidents as timeline representation
    alerts = storage.load_recent_alerts(limit=1000)
    incidents = storage.load_all_incidents() if hasattr(storage, "load_all_incidents") else []

    timeline_data = {
        "export_timestamp": datetime.utcnow().isoformat(),
        "alerts": [alert.to_dict() for alert in alerts],
        "incidents": [incident.to_dict() for incident in incidents],
        "summary": {
            "total_alerts": len(alerts),
            "total_incidents": len(incidents),
            "open_incidents": len([i for i in incidents if i.status == "open"]),
        },
    }

    out_path_obj = Path(out_path)
    out_path_obj.parent.mkdir(parents=True, exist_ok=True)

    with out_path_obj.open("w", encoding="utf-8") as f:
        json.dump(timeline_data, f, indent=2, default=str)


def export_timeline_text(storage: Storage, out_path: str | Path) -> None:
    """
    Export timeline events to text format.

    Args:
        storage: Storage backend to read from.
        out_path: Output file path.
    """
    alerts = storage.load_recent_alerts(limit=1000)
    incidents = storage.load_all_incidents() if hasattr(storage, "load_all_incidents") else []

    out_path_obj = Path(out_path)
    out_path_obj.parent.mkdir(parents=True, exist_ok=True)

    with out_path_obj.open("w", encoding="utf-8") as f:
        f.write("SOC Audit Timeline Export\n")
        f.write("=" * 60 + "\n")
        f.write(f"Export Date: {datetime.utcnow().isoformat()}\n")
        f.write(f"Total Alerts: {len(alerts)}\n")
        f.write(f"Total Incidents: {len(incidents)}\n")
        f.write(f"Open Incidents: {len([i for i in incidents if i.status == 'open'])}\n")
        f.write("\n")

        # Write incidents summary
        f.write("INCIDENTS SUMMARY\n")
        f.write("-" * 60 + "\n")
        for incident in incidents:
            f.write(f"\nIncident ID: {incident.id[:8]}...\n")
            f.write(f"  Title: {incident.title}\n")
            f.write(f"  Status: {incident.status}\n")
            f.write(f"  Created: {incident.created_ts.isoformat()}\n")
            f.write(f"  Updated: {incident.updated_ts.isoformat()}\n")
            f.write(f"  Severity: {incident.severity_max}\n")
            f.write(f"  RBA Max: {incident.rba_max or 'N/A'}\n")
            f.write(f"  Alert Count: {incident.alert_count}\n")
            if incident.notes:
                f.write(f"  Notes: {incident.notes}\n")

        # Write alerts (chronological)
        f.write("\n\nALERTS (Chronological)\n")
        f.write("-" * 60 + "\n")
        for alert in sorted(alerts, key=lambda x: x.timestamp):
            f.write(f"\n[{alert.timestamp.isoformat()}] {alert.severity.upper()}\n")
            f.write(f"  Module: {alert.module}\n")
            f.write(f"  Title: {alert.title}\n")
            f.write(f"  Source: {alert.source}\n")
            if alert.rba_score:
                f.write(f"  RBA: {alert.rba_score}\n")
            if alert.mitre_ids:
                f.write(f"  MITRE: {', '.join(alert.mitre_ids)}\n")
            if alert.incident_id:
                f.write(f"  Incident: {alert.incident_id[:8]}...\n")
            if alert.acked:
                f.write(f"  [ACKNOWLEDGED]\n")
            if alert.suppressed:
                f.write(f"  [SUPPRESSED]\n")


def export_incidents_json(storage: Storage, out_path: str | Path) -> None:
    """
    Export incidents to JSON format.

    Args:
        storage: Storage backend to read from.
        out_path: Output file path.
    """
    incidents = storage.load_all_incidents() if hasattr(storage, "load_all_incidents") else []

    incidents_data = {
        "export_timestamp": datetime.utcnow().isoformat(),
        "incidents": [incident.to_dict() for incident in incidents],
        "summary": {
            "total_incidents": len(incidents),
            "open_incidents": len([i for i in incidents if i.status == "open"]),
            "closed_incidents": len([i for i in incidents if i.status == "closed"]),
        },
    }

    out_path_obj = Path(out_path)
    out_path_obj.parent.mkdir(parents=True, exist_ok=True)

    with out_path_obj.open("w", encoding="utf-8") as f:
        json.dump(incidents_data, f, indent=2, default=str)
