"""MITRE ATT&CK mapping for findings and events.

This module provides functionality to map security findings to MITRE ATT&CK
tactics, techniques, and technique IDs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None  # type: ignore


@dataclass
class MitreMapping:
    """A mapping rule for finding MITRE ATT&CK associations."""

    title_contains: list[str]
    module: str | None = None
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    ids: list[str] = field(default_factory=list)


def load_mitre_mapping(path: str | Path) -> list[MitreMapping]:
    """
    Load MITRE ATT&CK mappings from a YAML file.

    Args:
        path: Path to the YAML mapping file.

    Returns:
        List of MitreMapping objects.

    Raises:
        RuntimeError: If YAML support is not available or file cannot be loaded.
        FileNotFoundError: If the mapping file does not exist.
    """
    if yaml is None:
        raise RuntimeError("MITRE mapping requires PyYAML.")

    mapping_path = Path(path)
    if not mapping_path.exists():
        return []  # Return empty list if file doesn't exist (non-fatal)

    with mapping_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    mappings = []
    for rule in data.get("mappings", []):
        match = rule.get("match", {})
        mitre = rule.get("mitre", {})

        mapping = MitreMapping(
            title_contains=match.get("title_contains", []),
            module=match.get("module"),
            tactics=mitre.get("tactics", []),
            techniques=mitre.get("techniques", []),
            ids=mitre.get("ids", []),
        )
        mappings.append(mapping)

    return mappings


def map_finding_to_mitre(
    finding: Any, mappings: list[MitreMapping] | None = None
) -> tuple[list[str], list[str], list[str]]:
    """
    Map a finding to MITRE ATT&CK tactics, techniques, and IDs.

    Args:
        finding: Finding object with at least 'title' and optionally 'module_name'.
        mappings: Optional pre-loaded mappings list. If None, returns empty lists.

    Returns:
        Tuple of (tactics, techniques, ids) lists.
    """
    if mappings is None:
        return ([], [], [])

    tactics: list[str] = []
    techniques: list[str] = []
    ids: list[str] = []

    finding_title = getattr(finding, "title", "")
    finding_module = getattr(finding, "module_name", None)

    for mapping in mappings:
        # Check module match (if specified in mapping)
        if mapping.module and finding_module != mapping.module:
            continue

        # Check title contains matches
        title_matches = True
        for pattern in mapping.title_contains:
            if pattern.lower() not in finding_title.lower():
                title_matches = False
                break

        if title_matches:
            tactics.extend(mapping.tactics)
            techniques.extend(mapping.techniques)
            ids.extend(mapping.ids)

    # Deduplicate while preserving order
    tactics = list(dict.fromkeys(tactics))
    techniques = list(dict.fromkeys(techniques))
    ids = list(dict.fromkeys(ids))

    return (tactics, techniques, ids)
