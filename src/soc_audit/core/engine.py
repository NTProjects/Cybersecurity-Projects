"""Execution engine for SOC auditing modules."""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

from soc_audit.core.config import merge_defaults
from soc_audit.core.interfaces import BaseModule, ModuleContext, ModuleResult


@dataclass(frozen=True)
class EngineResult:
    module_results: Sequence[ModuleResult]


class ModuleRegistry:
    """Discovers and instantiates modules from the modules package."""

    def __init__(self) -> None:
        self._modules: dict[str, type[BaseModule]] = {}

    def register(self, module_cls: type[BaseModule]) -> None:
        self._modules[module_cls.name] = module_cls

    def discover(self, package: str) -> None:
        package_module = importlib.import_module(package)
        for module_info in pkgutil.iter_modules(package_module.__path__, package_module.__name__ + "."):
            importlib.import_module(module_info.name)
        for module_cls in BaseModule.__subclasses__():
            self.register(module_cls)

    def get(self, name: str) -> type[BaseModule] | None:
        return self._modules.get(name)

    def available(self) -> Iterable[str]:
        return sorted(self._modules.keys())


class Engine:
    """Core engine that loads modules based on configuration."""

    def __init__(self, config: Mapping[str, Any]):
        self.config = config
        self.registry = ModuleRegistry()
        self.registry.discover("soc_audit.modules")

    def run(self) -> EngineResult:
        module_configs = self.config.get("modules", [])
        context = ModuleContext(self.config)
        results: list[ModuleResult] = []
        for module_entry in module_configs:
            if not module_entry.get("enabled", True):
                continue
            module_name = module_entry.get("name")
            if not module_name:
                continue
            module_cls = self.registry.get(module_name)
            if not module_cls:
                raise ValueError(f"Module '{module_name}' not found. Available: {self.registry.available()}")
            module_config = merge_defaults(module_entry.get("config", {}), module_cls.default_config())
            module = module_cls(module_config)
            results.append(module.run(context))
        return EngineResult(module_results=results)
