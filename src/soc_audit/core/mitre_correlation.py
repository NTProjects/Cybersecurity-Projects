"""MITRE ATT&CK Correlation Engine.

Phase 12.1: Detection Intelligence
- Technique chaining
- Kill-chain visualization
- Detection confidence scoring
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from soc_audit.core.models import AlertEvent


# MITRE ATT&CK Tactics (ordered by kill chain)
ATTACK_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Technique relationships (parent -> children)
TECHNIQUE_RELATIONSHIPS: dict[str, list[str]] = {
    # Example relationships - can be expanded
    "T1059": ["T1059.001", "T1059.002", "T1059.003"],  # Command and Scripting Interpreter
    "T1071": ["T1071.001", "T1071.002", "T1071.003", "T1071.004"],  # Application Layer Protocol
}


class TechniqueChain:
    """
    Represents a chain of MITRE ATT&CK techniques.
    
    Phase 12.1: Tracks related techniques observed across alerts/incidents.
    """
    
    def __init__(self, chain_id: str):
        """
        Initialize technique chain.
        
        Args:
            chain_id: Unique identifier for this chain.
        """
        self.chain_id = chain_id
        self.techniques: list[str] = []  # MITRE technique IDs
        self.tactics: list[str] = []  # Tactics in order
        self.alerts: list[str] = []  # Alert IDs in this chain
        self.incidents: list[str] = []  # Incident IDs
        self.hosts: set[str] = set()  # Hosts involved
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None
        self.confidence_score: float = 0.0  # 0.0 to 1.0
    
    def add_technique(self, technique_id: str, tactic: str | None = None) -> None:
        """Add a technique to the chain."""
        if technique_id not in self.techniques:
            self.techniques.append(technique_id)
        if tactic and tactic not in self.tactics:
            self.tactics.append(tactic)
    
    def add_alert(self, alert_id: str, timestamp: datetime) -> None:
        """Add an alert to the chain."""
        if alert_id not in self.alerts:
            self.alerts.append(alert_id)
        if not self.first_seen or timestamp < self.first_seen:
            self.first_seen = timestamp
        if not self.last_seen or timestamp > self.last_seen:
            self.last_seen = timestamp
    
    def calculate_confidence(self) -> float:
        """
        Calculate detection confidence score.
        
        Phase 12.1: Confidence based on:
        - Number of techniques in chain
        - Kill-chain progression
        - Time span
        - Number of alerts/incidents
        
        Returns:
            Confidence score (0.0 to 1.0).
        """
        score = 0.0
        
        # Technique count (more techniques = higher confidence)
        technique_score = min(len(self.techniques) / 10.0, 0.3)
        score += technique_score
        
        # Kill-chain progression (complete chains = higher confidence)
        if len(self.tactics) >= 3:
            progression_score = min(len(self.tactics) / 14.0, 0.3)
            score += progression_score
        
        # Alert/incident count (more evidence = higher confidence)
        evidence_score = min((len(self.alerts) + len(self.incidents)) / 20.0, 0.2)
        score += evidence_score
        
        # Time span (longer campaigns = higher confidence)
        if self.first_seen and self.last_seen:
            time_span = (self.last_seen - self.first_seen).total_seconds()
            if time_span > 0:
                # Normalize to days, cap at 30 days
                days = time_span / 86400
                time_score = min(days / 30.0, 0.2)
                score += time_score
        
        self.confidence_score = min(score, 1.0)
        return self.confidence_score
    
    def to_dict(self) -> dict[str, Any]:
        """Convert chain to dictionary."""
        return {
            "chain_id": self.chain_id,
            "techniques": self.techniques,
            "tactics": self.tactics,
            "alert_count": len(self.alerts),
            "incident_count": len(self.incidents),
            "host_count": len(self.hosts),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "confidence_score": self.confidence_score,
        }


class MITRECorrelationEngine:
    """
    MITRE ATT&CK correlation engine for detection intelligence.
    
    Phase 12.1: Analyzes alerts and incidents to identify technique chains and kill-chain progression.
    """
    
    def __init__(self, time_window_hours: int = 24):
        """
        Initialize correlation engine.
        
        Args:
            time_window_hours: Time window for correlating techniques (default: 24 hours).
        """
        self.time_window_hours = time_window_hours
        self.chains: dict[str, TechniqueChain] = {}
        self.technique_to_chains: defaultdict[str, set[str]] = defaultdict(set)
        self.alert_to_chain: dict[str, str] = {}  # alert_id -> chain_id
    
    def process_alert(self, alert: AlertEvent | dict[str, Any]) -> list[str]:
        """
        Process an alert and correlate with existing chains.
        
        Phase 12.1: Analyzes alert's MITRE techniques and links to existing chains or creates new ones.
        
        Args:
            alert: AlertEvent or alert dictionary with mitre_ids field.
        
        Returns:
            List of chain IDs this alert is associated with.
        """
        if isinstance(alert, dict):
            alert_id = alert.get("id", "")
            mitre_ids = alert.get("mitre_ids", [])
            timestamp_str = alert.get("timestamp", "")
            host_id = alert.get("host_id", "")
        else:
            alert_id = alert.id
            mitre_ids = alert.mitre_ids or []
            timestamp_str = alert.timestamp
            host_id = getattr(alert, "host_id", "")
        
        if not mitre_ids:
            return []
        
        # Parse timestamp
        try:
            if isinstance(timestamp_str, datetime):
                timestamp = timestamp_str
            else:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            timestamp = datetime.utcnow()
        
        # Find or create chains for these techniques
        associated_chains: list[str] = []
        
        for technique_id in mitre_ids:
            # Check if technique is already in a chain
            existing_chains = self.technique_to_chains.get(technique_id, set())
            
            # Filter chains within time window
            valid_chains = []
            for chain_id in existing_chains:
                chain = self.chains[chain_id]
                if chain.last_seen:
                    time_diff = (timestamp - chain.last_seen).total_seconds() / 3600
                    if time_diff <= self.time_window_hours:
                        valid_chains.append(chain_id)
            
            if valid_chains:
                # Add to existing chain(s)
                for chain_id in valid_chains:
                    chain = self.chains[chain_id]
                    chain.add_technique(technique_id)
                    chain.add_alert(alert_id, timestamp)
                    if host_id:
                        chain.hosts.add(host_id)
                    if chain_id not in associated_chains:
                        associated_chains.append(chain_id)
            else:
                # Create new chain
                chain_id = f"chain_{len(self.chains) + 1}"
                chain = TechniqueChain(chain_id)
                chain.add_technique(technique_id)
                chain.add_alert(alert_id, timestamp)
                if host_id:
                    chain.hosts.add(host_id)
                
                self.chains[chain_id] = chain
                self.technique_to_chains[technique_id].add(chain_id)
                associated_chains.append(chain_id)
        
        # Update confidence scores
        for chain_id in associated_chains:
            self.chains[chain_id].calculate_confidence()
        
        # Track alert-to-chain mapping
        if associated_chains:
            self.alert_to_chain[alert_id] = associated_chains[0]  # Primary chain
        
        return associated_chains
    
    def get_kill_chain_progression(self, chain_id: str) -> dict[str, Any]:
        """
        Get kill-chain progression for a technique chain.
        
        Phase 12.1: Visualizes which tactics have been observed in the chain.
        
        Args:
            chain_id: Chain identifier.
        
        Returns:
            Dictionary with kill-chain progression data.
        """
        if chain_id not in self.chains:
            return {}
        
        chain = self.chains[chain_id]
        
        # Map tactics to their positions in the kill chain
        progression = {}
        for i, tactic in enumerate(ATTACK_TACTICS):
            progression[tactic] = {
                "position": i,
                "observed": tactic in chain.tactics,
                "techniques": [
                    tech for tech in chain.techniques
                    # In real implementation, would map technique to tactic
                ],
            }
        
        return {
            "chain_id": chain_id,
            "progression": progression,
            "observed_tactics": chain.tactics,
            "total_tactics": len(ATTACK_TACTICS),
            "coverage": len(chain.tactics) / len(ATTACK_TACTICS),
        }
    
    def get_high_confidence_chains(self, min_confidence: float = 0.5) -> list[dict[str, Any]]:
        """
        Get chains with high confidence scores.
        
        Phase 12.1: Returns chains that likely represent real attack campaigns.
        
        Args:
            min_confidence: Minimum confidence score (0.0 to 1.0).
        
        Returns:
            List of chain dictionaries sorted by confidence (descending).
        """
        high_confidence = [
            chain.to_dict()
            for chain in self.chains.values()
            if chain.confidence_score >= min_confidence
        ]
        
        return sorted(high_confidence, key=lambda x: x["confidence_score"], reverse=True)
    
    def merge_chains(self, chain_id1: str, chain_id2: str) -> str:
        """
        Merge two chains (e.g., when they share techniques/hosts).
        
        Phase 12.1: Consolidates related chains.
        
        Args:
            chain_id1: First chain ID.
            chain_id2: Second chain ID.
        
        Returns:
            Merged chain ID (keeps chain_id1).
        """
        if chain_id1 not in self.chains or chain_id2 not in self.chains:
            return chain_id1
        
        chain1 = self.chains[chain_id1]
        chain2 = self.chains[chain_id2]
        
        # Merge chain2 into chain1
        for technique in chain2.techniques:
            chain1.add_technique(technique)
        for alert_id in chain2.alerts:
            if alert_id not in chain1.alerts:
                chain1.alerts.append(alert_id)
        for incident_id in chain2.incidents:
            if incident_id not in chain1.incidents:
                chain1.incidents.append(incident_id)
        chain1.hosts.update(chain2.hosts)
        
        # Update mappings
        for technique in chain2.techniques:
            self.technique_to_chains[technique].discard(chain_id2)
            self.technique_to_chains[technique].add(chain_id1)
        
        for alert_id in chain2.alerts:
            self.alert_to_chain[alert_id] = chain_id1
        
        # Remove chain2
        del self.chains[chain_id2]
        
        # Recalculate confidence
        chain1.calculate_confidence()
        
        return chain_id1
