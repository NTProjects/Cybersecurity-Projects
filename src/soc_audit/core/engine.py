"""Execution engine for SOC auditing modules."""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from soc_audit.core.config import merge_defaults
from soc_audit.core.interfaces import BaseModule, Finding, ModuleContext, ModuleResult
from soc_audit.modules.compliance_mapper import ComplianceMapper


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

            # Automatically run PortRiskAnalyzer when NetworkScanner runs
            if module_name == "network_scanner":
                port_risk_analyzer_cls = self.registry.get("port_risk_analyzer")
                if port_risk_analyzer_cls:
                    port_risk_config = self._transform_targets_for_port_risk_analyzer(module_config)
                    port_risk_module = port_risk_analyzer_cls(port_risk_config)
                    results.append(port_risk_module.run(context))

        # Collect all findings from all module results
        all_findings: list[Finding] = []
        for module_result in results:
            all_findings.extend(module_result.findings)

        # Apply compliance mapping if enabled
        if self.config.get("enable_compliance", True) and all_findings:
            compliance_config = dict(self.config)
            compliance_config["findings"] = all_findings
            compliance_mapper = ComplianceMapper(compliance_config)
            compliance_result = compliance_mapper.run(context)
            enriched_findings = list(compliance_result.findings)

            # Replace findings in module results with enriched findings
            # Create a mapping of original findings to enriched findings for matching
            finding_map: dict[str, Finding] = {}
            for enriched in enriched_findings:
                # Use title as key for matching (simple approach)
                finding_map[enriched.title] = enriched

            # Update module results with enriched findings
            updated_results: list[ModuleResult] = []
            for module_result in results:
                updated_findings: list[Finding] = []
                for finding in module_result.findings:
                    enriched = finding_map.get(finding.title, finding)
                    updated_findings.append(enriched)
                updated_results.append(
                    ModuleResult(
                        module_name=module_result.module_name,
                        started_at=module_result.started_at,
                        completed_at=module_result.completed_at,
                        findings=updated_findings,
                        metadata=module_result.metadata,
                    )
                )
            results = updated_results

        return EngineResult(module_results=results)

    @staticmethod
    def _transform_targets_for_port_risk_analyzer(network_scanner_config: Mapping[str, Any]) -> dict[str, Any]:
        """
        Transform NetworkScanner target format to PortRiskAnalyzer target format.

        NetworkScanner format: {"targets": [{"host": "...", "ports": [22, 80, 443]}]}
        PortRiskAnalyzer format: {"targets": [{"host": "...", "port": 22}, {"host": "...", "port": 80}, ...]}
        """
        targets: list[dict[str, Any]] = []
        network_targets = network_scanner_config.get("targets", [])
        for target in network_targets:
            host = target.get("host")
            ports = target.get("ports", [])
            for port in ports:
                targets.append({"host": host, "port": port})

        port_risk_config: dict[str, Any] = {
            "targets": targets,
            "timeout_seconds": network_scanner_config.get("timeout_seconds", 2.0),
        }
        return port_risk_config
