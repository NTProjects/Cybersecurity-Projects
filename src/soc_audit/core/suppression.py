"""Suppression rules for muting alerts.

This module provides functionality to define and apply suppression rules
that prevent certain alerts from being displayed or acted upon.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from soc_audit.core.models import AlertEvent


@dataclass
class SuppressionRule:
    """A rule that suppresses matching alerts."""

    id: str
    name: str
    enabled: bool = True
    match_module: str | None = None
    match_title_contains: list[str] = field(default_factory=list)
    match_mitre_ids: list[str] = field(default_factory=list)
    match_min_rba: int | None = None
    expires_ts: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "enabled": self.enabled,
            "match_module": self.match_module,
            "match_title_contains": self.match_title_contains,
            "match_mitre_ids": self.match_mitre_ids,
            "match_min_rba": self.match_min_rba,
            "expires_ts": self.expires_ts.isoformat() if self.expires_ts else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SuppressionRule:
        """Create from dictionary."""
        expires_ts = None
        if data.get("expires_ts"):
            expires_ts = datetime.fromisoformat(data["expires_ts"])

        return cls(
            id=data["id"],
            name=data["name"],
            enabled=data.get("enabled", True),
            match_module=data.get("match_module"),
            match_title_contains=data.get("match_title_contains", []),
            match_mitre_ids=data.get("match_mitre_ids", []),
            match_min_rba=data.get("match_min_rba"),
            expires_ts=expires_ts,
        )


def load_suppressions(path: str | Path) -> list[SuppressionRule]:
    """
    Load suppression rules from a JSON file.

    Args:
        path: Path to the JSON file.

    Returns:
        List of SuppressionRule objects.
    """
    path_obj = Path(path)
    if not path_obj.exists():
        return []  # Return empty list if file doesn't exist

    try:
        with path_obj.open("r", encoding="utf-8") as f:
            data = json.load(f)

        rules = []
        for rule_data in data.get("rules", []):
            rules.append(SuppressionRule.from_dict(rule_data))

        return rules
    except Exception:
        return []  # Return empty list on error


def save_suppressions(path: str | Path, rules: list[SuppressionRule]) -> None:
    """
    Save suppression rules to a JSON file.

    Args:
        path: Path to the JSON file.
        rules: List of SuppressionRule objects to save.
    """
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)

    data = {"rules": [rule.to_dict() for rule in rules]}

    with path_obj.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def event_is_suppressed(event: AlertEvent, rules: list[SuppressionRule]) -> bool:
    """
    Check if an event matches any enabled suppression rule.

    Args:
        event: The AlertEvent to check.
        rules: List of SuppressionRule objects.

    Returns:
        True if the event should be suppressed, False otherwise.
    """
    now = datetime.utcnow()

    for rule in rules:
        if not rule.enabled:
            continue

        # Check expiration
        if rule.expires_ts and rule.expires_ts < now:
            continue

        # Check module match
        if rule.match_module and event.module != rule.match_module:
            continue

        # Check title contains
        if rule.match_title_contains:
            title_lower = event.title.lower()
            if not any(keyword.lower() in title_lower for keyword in rule.match_title_contains):
                continue

        # Check MITRE IDs
        if rule.match_mitre_ids:
            if not any(mitre_id in event.mitre_ids for mitre_id in rule.match_mitre_ids):
                continue

        # Check minimum RBA
        if rule.match_min_rba is not None:
            if event.rba_score is None or event.rba_score < rule.match_min_rba:
                continue

        # All conditions matched - suppress
        return True

    return False


def upsert_rule(rules: list[SuppressionRule], rule: SuppressionRule) -> None:
    """
    Insert or update a suppression rule in the list.

    Args:
        rules: List of SuppressionRule objects (modified in-place).
        rule: The rule to insert or update.
    """
    # Find existing rule by ID
    for i, existing in enumerate(rules):
        if existing.id == rule.id:
            rules[i] = rule
            return

    # Not found - append
    rules.append(rule)
