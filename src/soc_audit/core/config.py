"""Configuration loading and validation utilities."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


def _load_yaml(raw_text: str) -> Mapping[str, Any]:
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("YAML support requires PyYAML.") from exc
    return yaml.safe_load(raw_text) or {}


def load_config(path: str | Path) -> Mapping[str, Any]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    raw_text = path.read_text(encoding="utf-8")
    if path.suffix in {".yaml", ".yml"}:
        return _load_yaml(raw_text)
    return json.loads(raw_text)


def merge_defaults(config: Mapping[str, Any], defaults: Mapping[str, Any]) -> Mapping[str, Any]:
    merged = dict(defaults)
    for key, value in config.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = merge_defaults(value, merged[key])
        else:
            merged[key] = value
    return merged
