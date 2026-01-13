"""Bridge between GUI and the core CLI/engine functionality.

This module provides the interface between the GUI components and the
underlying SOC audit engine. It ensures the GUI remains a thin wrapper
around the existing functionality without duplicating business logic.

Why this bridge exists:
    The SOC Audit Framework follows a CLI-first architecture where all
    business logic resides in the core engine. The GUI should not duplicate
    any scanning, analysis, or reporting logic. Instead, this bridge provides
    a clean programmatic interface to invoke the engine exactly as the CLI does.

How it preserves CLI-first architecture:
    - Uses the same config loading mechanism as the CLI
    - Instantiates the same Engine class used by the CLI
    - Returns the same EngineResult structure
    - Does not add any GUI-specific scanning logic
    - Any improvements to the engine automatically benefit both CLI and GUI

How the GUI will use it:
    1. User configures scan options in the GUI
    2. GUI saves configuration to a file or passes a config dict
    3. GUI instantiates GuiCliBridge with the config path
    4. GUI calls bridge.run() to execute the scan
    5. GUI receives EngineResult and displays findings in the UI
    6. GUI handles any exceptions and shows appropriate error dialogs

Responsibilities:
- Load configuration files using the existing config loader
- Instantiate and execute the Engine with loaded configuration
- Return EngineResult for GUI display (no printing or console output)
- Raise exceptions normally (GUI will handle them appropriately)
- Preserve all CLI functionality through programmatic access
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from soc_audit.core.config import load_config
from soc_audit.core.engine import Engine, EngineResult


class GuiCliBridge:
    """
    Bridge class for invoking the SOC Audit Engine from the GUI.

    This class provides a clean interface for the GUI to execute security
    scans without duplicating any engine logic. It loads configuration
    using the existing config system and returns results that the GUI
    can display.

    Example usage:
        bridge = GuiCliBridge("config/default.json")
        result = bridge.run()
        for module_result in result.module_results:
            for finding in module_result.findings:
                print(finding.title)

    Attributes:
        config_path: Path to the configuration file.
        config: Loaded configuration dictionary.
    """

    def __init__(self, config_path: str | Path) -> None:
        """
        Initialize the bridge with a configuration file path.

        Args:
            config_path: Path to the JSON or YAML configuration file.
                         The file must exist and be readable.

        Raises:
            FileNotFoundError: If the config file does not exist.
            json.JSONDecodeError: If the config file is invalid JSON.
            RuntimeError: If YAML parsing fails (for .yaml/.yml files).
        """
        self.config_path = Path(config_path)
        self.config: Mapping[str, Any] = load_config(self.config_path)

    def run(self) -> EngineResult:
        """
        Execute the SOC Audit Engine and return results.

        This method instantiates the Engine with the loaded configuration
        and runs all enabled modules. Results are returned directly without
        any console output, allowing the GUI to handle display.

        Returns:
            EngineResult containing all module results and findings.

        Raises:
            ValueError: If a configured module is not found.
            FileNotFoundError: If a module's target file is not found.
            RuntimeError: If a module encounters an unrecoverable error.
        """
        engine = Engine(self.config)
        return engine.run()
