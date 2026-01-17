"""Unified Security Dashboard.

Phase 18.1: SOC Command Platform
- Network + host + identity
- Risk posture score
- Executive view
"""
from __future__ import annotations

from typing import Any


class SecurityDashboard:
    """
    Unified security dashboard aggregator.
    
    Phase 18.1: Combines network, host, and identity data into unified view.
    """
    
    def __init__(self, storage: Any):
        """
        Initialize security dashboard.
        
        Args:
            storage: Storage backend for querying data.
        """
        self.storage = storage
    
    def get_risk_posture_score(self) -> dict[str, Any]:
        """
        Calculate overall risk posture score.
        
        Phase 18.1: Aggregates risk across network, hosts, and identity.
        
        Returns:
            Dictionary with risk posture metrics.
        """
        # Get all alerts
        alerts = self.storage.list_alerts({"limit": 10000})
        
        # Calculate risk components
        total_alerts = len(alerts)
        critical_alerts = len([a for a in alerts if a.get("severity") == "critical"])
        high_alerts = len([a for a in alerts if a.get("severity") == "high"])
        
        # Calculate average RBA score
        rba_scores = [a.get("rba_score", 0) for a in alerts if a.get("rba_score")]
        avg_rba = sum(rba_scores) / len(rba_scores) if rba_scores else 0
        
        # Get incidents
        incidents = self.storage.list_incidents({})
        open_incidents = len([i for i in incidents if i.get("status") != "closed"])
        
        # Calculate risk posture (0-100, higher = more risk)
        risk_score = 0
        risk_score += min(critical_alerts * 10, 40)  # Critical alerts contribute up to 40 points
        risk_score += min(high_alerts * 5, 30)  # High alerts contribute up to 30 points
        risk_score += min(avg_rba / 2, 20)  # RBA score contributes up to 20 points
        risk_score += min(open_incidents * 2, 10)  # Open incidents contribute up to 10 points
        risk_score = min(risk_score, 100)
        
        return {
            "risk_posture_score": int(risk_score),
            "risk_level": self._get_risk_level(risk_score),
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "average_rba": round(avg_rba, 2),
            "open_incidents": open_incidents,
            "components": {
                "network": self._calculate_network_risk(),
                "hosts": self._calculate_host_risk(),
                "identity": self._calculate_identity_risk(),
            },
        }
    
    def _get_risk_level(self, score: float) -> str:
        """Get risk level from score."""
        if score >= 75:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        else:
            return "low"
    
    def _calculate_network_risk(self) -> dict[str, Any]:
        """Calculate network risk component."""
        alerts = self.storage.list_alerts({"limit": 1000})
        network_alerts = [a for a in alerts if "network" in a.get("module", "").lower() or "port" in a.get("title", "").lower()]
        
        return {
            "alert_count": len(network_alerts),
            "risk_score": min(len(network_alerts) * 2, 100),
        }
    
    def _calculate_host_risk(self) -> dict[str, Any]:
        """Calculate host risk component."""
        hosts = self.storage.list_hosts()
        incidents = self.storage.list_incidents({})
        
        hosts_with_incidents = set()
        for incident in incidents:
            host_id = incident.get("host_id")
            if host_id:
                hosts_with_incidents.add(host_id)
        
        return {
            "total_hosts": len(hosts),
            "hosts_with_incidents": len(hosts_with_incidents),
            "risk_score": min((len(hosts_with_incidents) / len(hosts) * 100) if hosts else 0, 100),
        }
    
    def _calculate_identity_risk(self) -> dict[str, Any]:
        """Calculate identity risk component."""
        alerts = self.storage.list_alerts({"limit": 1000})
        identity_alerts = [a for a in alerts if "user" in a.get("title", "").lower() or "account" in a.get("title", "").lower()]
        
        return {
            "alert_count": len(identity_alerts),
            "risk_score": min(len(identity_alerts) * 3, 100),
        }
    
    def get_executive_view(self) -> dict[str, Any]:
        """
        Get executive-level summary view.
        
        Phase 18.1: High-level metrics for executives.
        
        Returns:
            Dictionary with executive summary.
        """
        risk_posture = self.get_risk_posture_score()
        incidents = self.storage.list_incidents({})
        
        return {
            "risk_posture": {
                "score": risk_posture["risk_posture_score"],
                "level": risk_posture["risk_level"],
            },
            "incidents": {
                "total": len(incidents),
                "open": len([i for i in incidents if i.get("status") != "closed"]),
                "closed": len([i for i in incidents if i.get("status") == "closed"]),
            },
            "alerts": {
                "total": risk_posture["total_alerts"],
                "critical": risk_posture["critical_alerts"],
                "high": risk_posture["high_alerts"],
            },
            "hosts": risk_posture["components"]["hosts"],
        }
