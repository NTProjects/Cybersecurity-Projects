# Cybersecurity-Projects
A collection of hands-on cybersecurity projects focused on SOC analyst skills, including threat detection, log analysis, incident response, SIEM monitoring, and security operations workflows.

## SOC Auditing & Intrusion Detection Framework
This repository now includes a modular, extensible SOC auditing framework designed for professional security teams.

### Project Structure
```
config/
  default.json           # Configuration-driven module execution
docs/
  ARCHITECTURE.md        # Architecture and extension points
src/
  soc_audit/
    cli.py               # CLI entry point
    core/                # Engine, config loader, shared interfaces
    modules/             # Built-in detection modules
    reporting/           # Report rendering utilities
```

### Quick Start (CLI MVP)
```
python -m soc_audit.cli --config config/default.json
```

### Adding Modules
1. Create a new module under `src/soc_audit/modules/`.
2. Extend `BaseModule` and set a unique `name`.
3. Add configuration under `modules` in the config file.
4. The engine automatically discovers modules at runtime.
