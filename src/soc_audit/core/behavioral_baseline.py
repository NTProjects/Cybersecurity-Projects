"""Behavioral Baseline Engine.

Phase 12.2: Detection Intelligence
- Host/entity baselining
- Deviation detection
- Risk amplification (RBA integration)
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from soc_audit.core.models import AlertEvent


class EntityBaseline:
    """
    Baseline for a single entity (host, IP, user, port).
    
    Phase 12.2: Tracks normal behavior patterns for entities.
    """
    
    def __init__(self, entity_type: str, entity_id: str):
        """
        Initialize entity baseline.
        
        Args:
            entity_type: Type of entity (host, ip, user, port).
            entity_id: Entity identifier.
        """
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.alert_counts: defaultdict[str, int] = defaultdict(int)  # module -> count
        self.severity_counts: defaultdict[str, int] = defaultdict(int)  # severity -> count
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None
        self.total_alerts = 0
        self.unique_modules: set[str] = set()
        self.alert_frequency: float = 0.0  # Alerts per day
    
    def add_alert(self, alert: AlertEvent | dict[str, Any]) -> None:
        """Add an alert to the baseline."""
        if isinstance(alert, dict):
            module = alert.get("module", "unknown")
            severity = alert.get("severity", "info")
            timestamp_str = alert.get("timestamp", "")
        else:
            module = alert.module
            severity = alert.severity
            timestamp_str = alert.timestamp
        
        self.alert_counts[module] += 1
        self.severity_counts[severity] += 1
        self.total_alerts += 1
        self.unique_modules.add(module)
        
        # Parse timestamp
        try:
            if isinstance(timestamp_str, datetime):
                timestamp = timestamp_str
            else:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            timestamp = datetime.utcnow()
        
        if not self.first_seen or timestamp < self.first_seen:
            self.first_seen = timestamp
        if not self.last_seen or timestamp > self.last_seen:
            self.last_seen = timestamp
        
        # Calculate frequency
        if self.first_seen and self.last_seen:
            days = (self.last_seen - self.first_seen).total_seconds() / 86400
            if days > 0:
                self.alert_frequency = self.total_alerts / days
    
    def get_deviation_score(self, alert: AlertEvent | dict[str, Any]) -> float:
        """
        Calculate deviation score for an alert (0.0 to 1.0).
        
        Phase 12.2: Higher score = more unusual behavior.
        
        Args:
            alert: Alert to check against baseline.
        
        Returns:
            Deviation score (0.0 = normal, 1.0 = highly unusual).
        """
        if isinstance(alert, dict):
            module = alert.get("module", "unknown")
            severity = alert.get("severity", "info")
        else:
            module = alert.module
            severity = alert.severity
        
        score = 0.0
        
        # New module (never seen before)
        if module not in self.unique_modules:
            score += 0.4
        
        # Unusual severity for this entity
        total_severity = sum(self.severity_counts.values())
        if total_severity > 0:
            severity_ratio = self.severity_counts.get(severity, 0) / total_severity
            if severity_ratio < 0.1:  # Less than 10% of alerts have this severity
                score += 0.3
        
        # Frequency spike (more alerts than normal)
        if self.alert_frequency > 0:
            # Check if this would be a spike (simplified - would need time window)
            if self.total_alerts > 0:
                module_ratio = self.alert_counts.get(module, 0) / self.total_alerts
                if module_ratio < 0.05:  # This module is < 5% of normal alerts
                    score += 0.3
        
        return min(score, 1.0)


class BehavioralBaselineEngine:
    """
    Behavioral baseline engine for detection intelligence.
    
    Phase 12.2: Builds baselines for entities and detects deviations.
    """
    
    def __init__(self, baseline_window_days: int = 30):
        """
        Initialize baseline engine.
        
        Args:
            baseline_window_days: Number of days to use for baseline (default: 30).
        """
        self.baseline_window_days = baseline_window_days
        self.baselines: dict[str, EntityBaseline] = {}  # entity_key -> baseline
        self.deviation_threshold = 0.5  # Alert is deviant if score >= threshold
    
    def _get_entity_key(self, entity_type: str, entity_id: str) -> str:
        """Generate entity key."""
        return f"{entity_type}:{entity_id}"
    
    def process_alert(self, alert: AlertEvent | dict[str, Any]) -> dict[str, Any]:
        """
        Process an alert and check for behavioral deviations.
        
        Phase 12.2: Updates baselines and calculates deviation scores.
        
        Args:
            alert: AlertEvent or alert dictionary.
        
        Returns:
            Dictionary with deviation analysis results.
        """
        if isinstance(alert, dict):
            host_id = alert.get("host_id", "")
            entity_keys = alert.get("entity_keys", {})
        else:
            host_id = getattr(alert, "host_id", "")
            entity_keys = getattr(alert, "entity_keys", {})
        
        deviations = {}
        
        # Check host baseline
        if host_id:
            host_key = self._get_entity_key("host", host_id)
            if host_key not in self.baselines:
                self.baselines[host_key] = EntityBaseline("host", host_id)
            
            baseline = self.baselines[host_key]
            deviation_score = baseline.get_deviation_score(alert)
            baseline.add_alert(alert)
            
            if deviation_score >= self.deviation_threshold:
                deviations["host"] = {
                    "entity_id": host_id,
                    "deviation_score": deviation_score,
                    "reason": self._get_deviation_reason(baseline, alert),
                }
        
        # Check entity baselines (IPs, users, ports)
        for entity_type, entity_id in entity_keys.items():
            if not entity_id:
                continue
            
            entity_key = self._get_entity_key(entity_type, entity_id)
            if entity_key not in self.baselines:
                self.baselines[entity_key] = EntityBaseline(entity_type, entity_id)
            
            baseline = self.baselines[entity_key]
            deviation_score = baseline.get_deviation_score(alert)
            baseline.add_alert(alert)
            
            if deviation_score >= self.deviation_threshold:
                deviations[entity_type] = {
                    "entity_id": entity_id,
                    "deviation_score": deviation_score,
                    "reason": self._get_deviation_reason(baseline, alert),
                }
        
        return {
            "has_deviations": len(deviations) > 0,
            "deviations": deviations,
            "max_deviation_score": max([d["deviation_score"] for d in deviations.values()]) if deviations else 0.0,
        }
    
    def _get_deviation_reason(self, baseline: EntityBaseline, alert: AlertEvent | dict[str, Any]) -> str:
        """Get human-readable reason for deviation."""
        if isinstance(alert, dict):
            module = alert.get("module", "unknown")
            severity = alert.get("severity", "info")
        else:
            module = alert.module
            severity = alert.severity
        
        reasons = []
        
        if module not in baseline.unique_modules:
            reasons.append(f"new module: {module}")
        
        if baseline.total_alerts > 0:
            module_ratio = baseline.alert_counts.get(module, 0) / baseline.total_alerts
            if module_ratio < 0.05:
                reasons.append(f"unusual module frequency: {module}")
        
        return "; ".join(reasons) if reasons else "behavioral anomaly"
    
    def get_baseline_summary(self, entity_type: str | None = None) -> dict[str, Any]:
        """
        Get summary of all baselines.
        
        Phase 12.2: Returns baseline statistics.
        
        Args:
            entity_type: Optional filter by entity type.
        
        Returns:
            Dictionary with baseline summary.
        """
        filtered_baselines = [
            baseline for baseline in self.baselines.values()
            if not entity_type or baseline.entity_type == entity_type
        ]
        
        return {
            "total_entities": len(filtered_baselines),
            "total_alerts": sum(b.total_alerts for b in filtered_baselines),
            "average_frequency": sum(b.alert_frequency for b in filtered_baselines) / len(filtered_baselines) if filtered_baselines else 0.0,
            "entities_by_type": {
                entity_type: len([b for b in filtered_baselines if b.entity_type == entity_type])
                for entity_type in set(b.entity_type for b in filtered_baselines)
            },
        }
    
    def amplify_rba_score(self, alert: AlertEvent | dict[str, Any], base_rba: int) -> int:
        """
        Amplify RBA score based on behavioral deviations.
        
        Phase 12.2: Increases risk score for deviant behavior.
        
        Args:
            alert: AlertEvent or alert dictionary.
            base_rba: Base RBA score.
        
        Returns:
            Amplified RBA score.
        """
        deviation_analysis = self.process_alert(alert)
        
        if not deviation_analysis["has_deviations"]:
            return base_rba
        
        # Amplify based on max deviation score
        max_deviation = deviation_analysis["max_deviation_score"]
        amplification_factor = 1.0 + (max_deviation * 0.5)  # Up to 50% increase
        
        amplified = int(base_rba * amplification_factor)
        return min(amplified, 100)  # Cap at 100
