"""Text report formatting for Phase 9.3 exports."""
from __future__ import annotations

from datetime import datetime
from typing import Any


def format_incident_report_text(report_data: dict[str, Any]) -> str:
    """
    Phase 9.3: Format incident report as human-readable text.
    
    Args:
        report_data: Incident report dict from backend.
    
    Returns:
        Formatted text report.
    """
    lines = []
    
    # Header
    lines.append("=" * 80)
    lines.append("INCIDENT REPORT")
    lines.append("=" * 80)
    lines.append("")
    
    # Metadata
    generated_at = report_data.get("generated_at", "")
    if generated_at:
        try:
            dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
            lines.append(f"Generated: {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        except Exception:
            lines.append(f"Generated: {generated_at}")
    lines.append("")
    
    # Summary
    lines.append("SUMMARY")
    lines.append("-" * 80)
    lines.append(f"Total Incidents:     {report_data.get('total_incidents', 0)}")
    lines.append(f"Open Incidents:      {report_data.get('open_incidents', 0)}")
    lines.append(f"Closed Incidents:    {report_data.get('closed_incidents', 0)}")
    
    mttr = report_data.get("mttr_seconds")
    if mttr is not None:
        hours = int(mttr // 3600)
        minutes = int((mttr % 3600) // 60)
        seconds = int(mttr % 60)
        lines.append(f"MTTR:                {hours:02d}:{minutes:02d}:{seconds:02d}")
    else:
        lines.append("MTTR:                N/A (no closed incidents)")
    
    # Aging buckets
    aging = report_data.get("aging_buckets", {})
    if aging and any(aging.values()):
        lines.append("")
        lines.append("Open Incident Aging:")
        lines.append(f"  < 1 hour:          {aging.get('<1h', 0)}")
        lines.append(f"  1-4 hours:         {aging.get('1-4h', 0)}")
        lines.append(f"  4-24 hours:        {aging.get('4-24h', 0)}")
        lines.append(f"  > 24 hours:        {aging.get('>24h', 0)}")
    
    lines.append("")
    lines.append("=" * 80)
    lines.append("INCIDENT DETAILS")
    lines.append("=" * 80)
    lines.append("")
    
    # Incident table header
    header = f"{'ID':<12} {'Status':<8} {'Severity':<10} {'RBA':<6} {'Alerts':<8} {'Host':<15} {'Created':<20}"
    lines.append(header)
    lines.append("-" * 80)
    
    # Incident rows
    incidents = report_data.get("incidents", [])
    for incident in sorted(incidents, key=lambda x: x.get("created_ts", ""), reverse=True):
        incident_id = incident.get("incident_id", "")[:12]
        status = incident.get("status", "")[:8]
        severity = incident.get("severity_max", "")[:10]
        rba = incident.get("rba_max") or "-"
        alert_count = incident.get("alert_count", 0)
        host_id = (incident.get("host_id") or "-")[:15]
        created_ts = incident.get("created_ts", "")
        
        # Format created_ts
        try:
            dt = datetime.fromisoformat(created_ts.replace("Z", "+00:00"))
            created_str = dt.strftime("%Y-%m-%d %H:%M:%S")[:20]
        except Exception:
            created_str = created_ts[:20]
        
        row = f"{incident_id:<12} {status:<8} {severity:<10} {str(rba):<6} {alert_count:<8} {host_id:<15} {created_str:<20}"
        lines.append(row)
    
    if not incidents:
        lines.append("(No incidents)")
    
    lines.append("")
    lines.append("=" * 80)
    
    return "\n".join(lines)


def format_host_report_text(report_data: dict[str, Any]) -> str:
    """
    Phase 9.3: Format host report as human-readable text.
    
    Args:
        report_data: Host report dict from backend.
    
    Returns:
        Formatted text report.
    """
    lines = []
    
    # Header
    lines.append("=" * 80)
    lines.append("HOST REPORT")
    lines.append("=" * 80)
    lines.append("")
    
    # Metadata
    generated_at = report_data.get("generated_at", "")
    if generated_at:
        try:
            dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
            lines.append(f"Generated: {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        except Exception:
            lines.append(f"Generated: {generated_at}")
    lines.append("")
    
    # Summary
    lines.append("SUMMARY")
    lines.append("-" * 80)
    lines.append(f"Total Hosts:     {report_data.get('total_hosts', 0)}")
    lines.append(f"Online Hosts:    {report_data.get('online_hosts', 0)}")
    lines.append(f"Offline Hosts:   {report_data.get('offline_hosts', 0)}")
    lines.append("")
    lines.append("=" * 80)
    lines.append("HOST DETAILS")
    lines.append("=" * 80)
    lines.append("")
    
    # Host table header
    header = f"{'Host ID':<20} {'Host Name':<20} {'Status':<10} {'Incidents':<10} {'Open':<6} {'Last Seen':<20}"
    lines.append(header)
    lines.append("-" * 80)
    
    # Host rows
    hosts = report_data.get("hosts", [])
    for host in sorted(hosts, key=lambda x: x.get("last_seen_ts", ""), reverse=True):
        host_id = host.get("host_id", "")[:20]
        host_name = (host.get("host_name") or "(unnamed)")[:20]
        status = host.get("status", "")[:10]
        incident_count = host.get("incident_count", 0)
        open_incidents = host.get("open_incidents", 0)
        last_seen_ts = host.get("last_seen_ts", "")
        
        # Format last_seen_ts
        try:
            dt = datetime.fromisoformat(last_seen_ts.replace("Z", "+00:00"))
            last_seen_str = dt.strftime("%Y-%m-%d %H:%M:%S")[:20]
        except Exception:
            last_seen_str = last_seen_ts[:20]
        
        row = f"{host_id:<20} {host_name:<20} {status:<10} {incident_count:<10} {open_incidents:<6} {last_seen_str:<20}"
        lines.append(row)
    
    if not hosts:
        lines.append("(No hosts)")
    
    lines.append("")
    lines.append("=" * 80)
    
    return "\n".join(lines)
