# SOC Audit Framework Architecture

## Goals
- Modular, plugin-based framework for SOC analysts and auditors.
- Clear separation of detection, compliance, and reporting concerns.
- Configuration-driven module execution.

## Module Discovery
- The core engine discovers modules dynamically from `soc_audit.modules`.
- Each module extends `BaseModule` and declares a unique `name`.
- Add new modules without changing core logic by dropping them into the package.

## Extension Points
- `BaseModule` for detection and analysis modules.
- `ComplianceRule` for compliance controls with standard metadata.
- Reporting renderer interface can be expanded to include HTML/PDF exports.

## Data Flow
1. CLI loads configuration.
2. Engine discovers modules and executes enabled modules.
3. Findings and metadata are aggregated in `EngineResult`.
4. Report renderer produces text or JSON output.
