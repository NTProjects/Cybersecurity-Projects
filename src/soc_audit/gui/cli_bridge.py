"""Bridge between GUI and the core CLI/engine functionality.

This module provides the interface between the GUI components and the
underlying SOC audit engine. It ensures the GUI remains a thin wrapper
around the existing functionality without duplicating business logic.

Responsibilities:
- Load and save configuration files
- Execute the engine with GUI-provided settings
- Stream results back to the GUI for display
- Handle errors and exceptions gracefully
- Preserve all CLI functionality through programmatic access
"""
