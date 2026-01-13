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

### Configuration

The framework supports configurable risk thresholds, port risk mappings, and protocol checks via the `risk` section in the configuration file:

```json
{
  "risk": {
    "severity_thresholds": {
      "info": 10,
      "low": 25,
      "medium": 50,
      "high": 75,
      "critical": 95
    },
    "port_risk_mappings": {
      "high_risk_ports": [21, 23, 135, 139, 445, 1433, 3306, 5432, 3389, 5900, 5985, 5986],
      "medium_risk_ports": [22, 80, 161, 443, 2049, 6379, 27017, 8080, 8443]
    },
    "protocol_checks": {
      "check_ftp_anonymous": true,
      "check_telnet": true
    }
  }
}
```

- **severity_thresholds**: Maps severity levels to risk scores (0-100 scale). Used for calculating risk scores from finding severity.
- **port_risk_mappings**: Defines which ports are categorized as high-risk or medium-risk.
- **protocol_checks**: Enables/disables specific protocol vulnerability checks (FTP anonymous access, Telnet detection).

All configuration values are optional and will fall back to sensible defaults if not specified.

### GUI Usage (Optional)

The SOC Audit Framework includes an optional graphical user interface. The CLI remains the default and recommended interface for automation and scripting.

**Installation (for live metrics):**

```bash
pip install -r requirements-gui.txt
```

**Launching the GUI:**

```powershell
# Windows PowerShell
$env:PYTHONPATH="src"
python -m soc_audit.gui
```

```bash
# Linux/macOS
PYTHONPATH=src python -m soc_audit.gui
```

> **Note:** If `psutil` is not installed, live metrics will show "N/A" but the GUI will still function normally.

**Supported Workflows:**
1. **Scan Configuration** — Select a config file and run security scans
2. **View Findings** — Browse, filter, and sort scan results
3. **Export Reports** — Save findings as JSON or plain text files

### GUI Features

The graphical interface provides the following capabilities:

- **Live System Metrics** — Real-time CPU, memory, network, and connection monitoring
  - Updates every second via Tkinter after() loop (no threading)
  - Graceful fallback to "N/A" if psutil unavailable or access denied
  - View > Refresh Metrics for manual update
- **Config Selection** — Browse and select JSON configuration files
- **Scan Execution** — Run the full audit engine with one click
- **Findings Table** — View all findings in a sortable, filterable table
  - Filter by module name
  - Filter by severity level
  - Search across title, description, and evidence
  - Click column headers to sort
- **Details Panel** — View complete finding information including:
  - Title, description, and severity
  - Risk score (when available)
  - Evidence data (pretty-printed JSON)
  - Compliance status and control IDs (when mapped)
  - Recommendations
- **Report Export** — Export scan results via File > Export Report
  - JSON format (machine-readable)
  - Text format (human-readable, matches CLI output)
- **Status Bar** — Real-time feedback on scan progress and actions

### CLI vs GUI

The SOC Audit Framework follows a **CLI-first architecture**:

| Aspect | CLI | GUI |
|--------|-----|-----|
| **Primary Use** | Automation, scripting, CI/CD | Interactive analysis |
| **Entry Point** | `python -m soc_audit.cli` | `python -m soc_audit.gui` |
| **Output** | Console text or JSON | Visual table + export |
| **Engine** | Same core engine | Same core engine |
| **Modules** | Same detection modules | Same detection modules |

Both interfaces use the identical `Engine`, `ModuleContext`, and `ReportRenderer` components. The GUI is a thin wrapper that provides visual interaction without duplicating business logic.