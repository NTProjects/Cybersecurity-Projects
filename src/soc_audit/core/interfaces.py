"""Core interfaces for extensible modules and results."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class Finding:
    """A single security finding returned by a module."""

    title: str
    description: str
    severity: str
    evidence: Mapping[str, Any] = field(default_factory=dict)
    recommendation: str | None = None


@dataclass(frozen=True)
class ModuleResult:
    """Standardized module output for reporting and aggregation."""

    module_name: str
    started_at: datetime
    completed_at: datetime
    findings: Iterable[Finding]
    metadata: Mapping[str, Any] = field(default_factory=dict)


class ModuleContext:
    """Shared context passed to all modules during a run."""

    def __init__(self, config: Mapping[str, Any]):
        self.config = config


class BaseModule(ABC):
    """Base class for all detection, analysis, and compliance modules."""

    name: str = "base"
    description: str = ""
    module_type: str = "generic"

    def __init__(self, config: Mapping[str, Any] | None = None):
        self.config = config or {}

    @classmethod
    def default_config(cls) -> Mapping[str, Any]:
        return {}

    @abstractmethod
    def run(self, context: ModuleContext) -> ModuleResult:
        """Execute the module and return structured results."""


class ComplianceRule(ABC):
    """Interface for compliance checks used by the compliance engine."""

    id: str
    title: str
    description: str
    standard: str

    @abstractmethod
    def evaluate(self, context: ModuleContext) -> Finding | None:
        """Return a finding if the rule fails, otherwise None."""
