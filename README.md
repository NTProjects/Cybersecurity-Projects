# Cybersecurity-Projects
A collection of hands-on cybersecurity projects focused on SOC analyst skills, including threat detection, log analysis, incident response, SIEM monitoring, and security operations workflows.

## SOC Auditing & Intrusion Detection Framework
This repository now includes a modular, extensible SOC auditing framework designed for professional security teams. The framework provides comprehensive security scanning, threat detection, compliance mapping, and enterprise-ready features including RBAC, audit logging, and real-time monitoring.

### Project Structure
```
config/
  default.json           # Configuration-driven module execution
docs/
  ARCHITECTURE.md        # Architecture and extension points
  ROADMAP.md            # Development roadmap (Phases 10-18)
  RBAC_MATRIX.md        # Role-based access control matrix
src/
  soc_audit/
    cli.py               # CLI entry point
    core/                # Engine, config loader, shared interfaces
    modules/             # Built-in detection modules
    reporting/           # Report rendering utilities
    server/              # FastAPI backend with RBAC & audit logging
    gui/                 # Tkinter-based graphical interface
    agent/               # Agent client for remote scanning
```

### Quick Start (CLI)
```bash
# Run with default configuration
python -m soc_audit.cli --config config/default.json

# View help
python -m soc_audit.cli --help
```

### Built-in Detection Modules

The framework includes the following detection and analysis modules:

#### 1. **Network Scanner** (`network_scanner`)
- Scans hosts for open TCP ports
- Basic service detection
- Supports configurable timeouts and target lists
- Automatically triggers `port_risk_analyzer` for discovered ports

#### 2. **Port Risk Analyzer** (`port_risk_analyzer`)
- Categorizes ports by risk level (high/medium/low)
- Protocol-aware security checks (FTP anonymous access, Telnet detection)
- Risk-based prioritization
- Automatically runs after network scans

#### 3. **Local Security Scanner** (`local_security_scanner`)
Comprehensive local system security scanning for Windows systems:

**Firewall Checks:**
- Windows Defender Firewall status (Domain/Private/Public profiles)
- Default inbound policy validation
- Firewall logging status
- Support for iptables/nftables (Linux, planned)

**Windows Defender Antivirus Checks:**
- Real-time protection status
- Tamper protection
- Cloud-delivered protection (MAPS)
- Automatic sample submission
- Signature update age validation
- Dev Drive protection
- Controlled Folder Access (Ransomware protection)
- Exclusion detection and reporting

**Device Security Checks:**
- Memory Integrity (Core Isolation)
- Secure Boot status
- TPM availability and readiness
- LSA Protection
- Microsoft Vulnerable Driver Blocklist
- Kernel-mode Hardware-enforced Stack Protection

**Exploit Protection Checks:**
- Control Flow Guard (CFG)
- Data Execution Prevention (DEP)
- Mandatory ASLR (Address Space Layout Randomization)
- Bottom-up ASLR
- High-entropy ASLR
- Validate exception chains (SEHOP)
- Validate heap integrity

**App & Browser Control Checks:**
- SmartScreen for apps and files
- SmartScreen for Microsoft Edge
- SmartScreen for Microsoft Store apps
- Phishing protection
- Potentially Unwanted App (PUA) blocking

#### 4. **Firewall Analyzer** (`firewall_analyzer`)
- Analyzes iptables firewall rules
- Detects overly permissive configurations
- Identifies insecure allow-all rules

#### 5. **Firewall State Ingestion** (`firewall_state_ingestion`)
- Collects firewall rules from Windows Defender Firewall
- Supports iptables/nftables parsing
- Provides structured rule data for analysis

#### 6. **Firewall Misconfiguration Detector** (`firewall_misconfig_detector`)
- Detects open ports vs. actual exposure
- Identifies shadowed/redundant rules
- Finds insecure allow-all rules
- Applies risk scoring to misconfigurations

#### 7. **Log Analyzer** (`log_analyzer`)
- Analyzes Linux authentication logs
- Detects repeated authentication failures
- Identifies potential brute-force attack patterns
- Configurable thresholds for alerting

#### 8. **Compliance Mapper** (`compliance_mapper`)
- Maps findings to compliance frameworks:
  - CISA Cross-Sector Cybersecurity Performance Goals
  - NIST 800-53 controls
  - CIS Controls v8
- Provides traceability from findings to controls
- Generates compliance evidence

### Enterprise Features (Phases 10-18)

#### Phase 10: Enterprise Hardening

**10.1 RBAC (Role-Based Access Control)**
- Endpoint-level authorization enforcement
- Role-based access control (Analyst, Admin, Agent roles)
- Explicit deny-by-default behavior
- Role matrix documentation (`docs/RBAC_MATRIX.md`)
- All API endpoints protected with role checks

**10.2 Audit Logging**
- Immutable audit log with hash chaining
- Logs: who, what, when, where (endpoint/object)
- Stored separately from operational data
- Tamper-evident design
- Automatic logging of all privileged/admin actions

**10.3 Multi-User Readiness**
- Concurrent analyst support
- Session isolation
- Transaction-safe write operations (rollback on failure)
- Database transaction integrity

**10.4 Observability**
- Structured logging (JSON format)
- Request correlation IDs
- Error logging with severity and context
- Performance instrumentation

#### Phase 11: Real-Time Without Polling

**11.1 WebSocket Event Bus**
- Push-only event delivery (no polling)
- Explicit subscription-based delivery
- Backpressure and rate limiting
- Real-time alert streaming

**11.2 GUI Event Rehydration**
- UI updates from events only
- Manual refresh available
- No auto-refresh loops

#### Phase 12: Detection Intelligence

**12.1 MITRE ATT&CK Correlation Engine**
- Technique mapping and chaining
- Kill-chain visualization
- Detection confidence scoring
- Multi-technique attack pattern detection

**12.2 Behavioral Baselines**
- Host/entity baselining
- Deviation detection
- Risk amplification (RBA integration)
- Reduces alert fatigue

#### Phase 13: Firewall & Network Security

- Firewall state ingestion (Windows/Linux)
- Firewall configuration viewer with rule parsing
- Misconfiguration detection (allow-all rules, shadow rules)
- Human-readable diffs and policy intent mapping

#### Phase 14: Compliance & Audit Automation

- CISA Crosswalk Engine
- NIST 800-53 and CIS Controls v8 mappings
- Evidence auto-collection with timestamps
- Exportable audit packets

#### Phase 15: Threat Hunting & Forensics

- Threat hunt workspace with historical event querying
- Timeline reconstruction
- Entity pivoting
- Forensic snapshots (host state capture, process/port snapshots)

#### Phase 16: Active Response

- Response playbooks (isolate host, block IP, kill process)
- Approval gates (Analyst → Admin approval)
- Full audit trail for all actions
- Dry-run mode for safety

#### Phase 17: Enterprise & Scale

- Multi-tenant support foundation
- Tenant isolation and tenant-aware RBAC
- HA & storage backends (PostgreSQL support planned)

#### Phase 18: SOC Command Platform

- Unified security dashboard (network + host + identity)
- Risk posture scoring
- Executive view
- Analyst & auditor modes (read-only audit mode)
- External integrations (SIEM export, SOAR hooks, ticketing)

### Adding Modules
1. Create a new module under `src/soc_audit/modules/`.
2. Extend `BaseModule` and set a unique `name`.
3. Add configuration under `modules` in the config file.
4. The engine automatically discovers modules at runtime.

### Configuration

The framework supports extensive configuration via `config/default.json`. Key configuration sections include:

#### Risk Configuration
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

#### Local Security Scans Configuration
Comprehensive local security scanning configuration:

```json
{
  "local_security_scans": {
    "enabled": true,
    "firewall": {
      "enabled": true,
      "check_firewall_enabled": true,
      "check_default_inbound_policy": true,
      "check_allow_all_rules": true,
      "check_open_inbound_rules": true,
      "check_logging_enabled": true,
      "platforms": {
        "windows_defender_firewall": true,
        "iptables": true,
        "nftables": true
      }
    },
    "windows_defender": {
      "enabled": true,
      "check_real_time_protection": true,
      "check_tamper_protection": true,
      "check_cloud_protection": true,
      "check_automatic_sample_submission": true,
      "check_signature_updates": true,
      "check_dev_drive_protection": true,
      "check_controlled_folder_access": true,
      "check_exclusions": true
    },
    "device_security": {
      "enabled": true,
      "check_memory_integrity": true,
      "check_secure_boot": true,
      "check_tpm": true,
      "check_lsa_protection": true,
      "check_vulnerable_driver_blocklist": true,
      "check_kernel_stack_protection": true
    },
    "exploit_protection": {
      "enabled": true,
      "check_cfg": true,
      "check_dep": true,
      "check_mandatory_aslr": true,
      "check_bottom_up_aslr": true,
      "check_high_entropy_aslr": true,
      "check_sehop": true,
      "check_heap_integrity": true
    },
    "app_browser_control": {
      "enabled": true,
      "check_smartscreen_apps": true,
      "check_smartscreen_edge": true,
      "check_smartscreen_store": true,
      "check_phishing_protection": true,
      "check_pua_blocking": true
    }
  }
}
```

#### Module Configuration
Enable/disable and configure modules:

```json
{
  "modules": [
    {
      "name": "network_scanner",
      "enabled": true,
      "config": {
        "targets": [
          {
            "host": "127.0.0.1",
            "ports": [22, 80, 443]
          }
        ],
        "timeout_seconds": 1.0
      }
    },
    {
      "name": "local_security_scanner",
      "enabled": true
    }
  ]
}
```

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
4. **SOC Workflow** — Acknowledge alerts, suppress similar alerts, manage incidents, export timeline

### Phase 5.5: SOC Workflow Features

The framework includes comprehensive SOC workflow capabilities:

#### Persistence

Alerts, incidents, and timeline events are persisted to disk for analysis and reporting:

- **Backend**: SQLite (default) or JSON fallback
- **Location**: `data/soc_audit.db` (SQLite) or `data/soc_audit_store.json` (JSON)
- **Configuration**: Set `persistence.enabled` to `false` in `config/default.json` to disable

#### Incident Grouping

Alerts are automatically grouped into incidents based on:

- Same module + same primary entity (IP/user)
- Same module + title similarity
- Same MITRE ID within time window (default: 5 minutes)

Incidents can be:
- **Opened/Closed** — Via Incidents menu
- **Annotated** — Add notes via Incidents > Add Note...
- **Exported** — Via File > Export Incidents...

#### Suppression Rules

Suppress alerts matching specific criteria:

- **Module match** — Suppress all alerts from a specific module
- **Title keywords** — Suppress alerts containing specific words in title
- **MITRE IDs** — Suppress alerts with specific MITRE ATT&CK technique IDs
- **RBA threshold** — Suppress alerts below a minimum RBA score

Suppression rules are stored in `config/suppressions.json` and persist across sessions.

#### Export Options

- **Export Timeline** — File > Export Timeline... (JSON or TXT format)
  - Includes all alerts and incidents with timestamps
  - Summary statistics included
- **Export Incidents** — File > Export Incidents... (JSON format)
  - Complete incident data with associated alerts

#### Alert Management

- **Acknowledge** — Right-click alert > Acknowledge (or Alerts menu)
- **Suppress Similar** — Right-click alert > Suppress Similar... (creates suppression rule)
- **View Incident** — Right-click alert > View Incident (jump to incident)

All actions are logged to the timeline for audit purposes.

### GUI Features

The graphical interface provides the following capabilities:

- **Live System Metrics** — Real-time CPU, memory, network, and connection monitoring
  - Updates every second via Tkinter after() loop (no threading)
  - Graceful fallback to "N/A" if psutil unavailable or access denied
  - View > Refresh Metrics for manual update
  
- **SOC Workflow Features** — Alert management, incident grouping, and persistence
  - **Alert Acknowledgement** — Mark alerts as acknowledged via right-click context menu
  - **Suppression Rules** — Mute similar alerts using configurable rules (module, title keywords, MITRE IDs, RBA thresholds)
  - **Incident Grouping** — Automatic grouping of related alerts into incidents based on similarity heuristics
  - **Persistence** — SQLite database (default) or JSON fallback for storing alerts, incidents, and timeline
  - **Export** — Export timeline and incidents to JSON or text format for reporting
  
- **Scanning & Analysis**
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
    - MITRE ATT&CK technique IDs
  
- **Reporting & Export**
  - **Report Export** — Export scan results via File > Export Report
    - JSON format (machine-readable)
    - Text format (human-readable, matches CLI output)
  - **Timeline Export** — Export audit timeline with all events
  - **Incident Export** — Export incident data with associated alerts
  
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

### Server Mode (FastAPI Backend)

The framework includes a FastAPI-based backend server with enterprise features:

**Start the server:**
```bash
python -m soc_audit.server.main
# Server runs on http://127.0.0.1:8001 by default
```

**Features:**
- RESTful API for scanning, alerts, incidents, and reports
- WebSocket support for real-time event streaming
- RBAC enforcement on all endpoints
- Immutable audit logging
- Multi-user concurrent access support
- Request correlation IDs
- Structured logging

**API Endpoints:**
- `GET /api/v1/hosts` — List registered hosts
- `POST /api/v1/ingest` — Ingest alerts (requires API key)
- `POST /api/v1/ingest/batch` — Batch ingest alerts
- `GET /api/v1/alerts` — List alerts (RBAC protected)
- `GET /api/v1/incidents` — List incidents (RBAC protected)
- `POST /api/v1/reports/generate` — Generate audit reports
- `WS /api/v1/ws` — WebSocket event stream

See `docs/RBAC_MATRIX.md` for role permissions.

### Agent Mode

Remote scanning via agent clients:

```bash
python -m soc_audit.agent --config config/default.json
```

**Features:**
- Connects to SOC Audit server
- Performs local scans and sends results
- Heartbeat monitoring
- Automatic retry on connection failures
- Batch alert ingestion

### Key Functions & Capabilities

#### Security Scanning
- **Network scanning** — Port discovery and service detection
- **Local security scanning** — Comprehensive Windows Defender and system security checks
- **Firewall analysis** — Rule parsing and misconfiguration detection
- **Log analysis** — Authentication failure detection and brute-force pattern recognition

#### Threat Detection
- **MITRE ATT&CK correlation** — Technique mapping and attack chain detection
- **Behavioral baselines** — Host/entity deviation detection
- **Risk-based analysis (RBA)** — Dynamic risk scoring and amplification

#### Compliance & Auditing
- **Compliance mapping** — CISA, NIST 800-53, CIS Controls v8
- **Evidence collection** — Timestamped, immutable audit artifacts
- **Audit logging** — Immutable, tamper-evident action logs
- **Role-based access control** — Enterprise-grade authorization

#### Operations
- **Incident management** — Automatic grouping and lifecycle tracking
- **Alert suppression** — Configurable rules to reduce noise
- **Timeline reconstruction** — Full event history with entity pivoting
- **Forensic snapshots** — Host state capture and change tracking

### Development

**Project Status:**
- ✅ Phases 10-18 completed and verified
- ✅ Enterprise hardening (RBAC, audit logging, multi-user support)
- ✅ Real-time event streaming via WebSocket
- ✅ Detection intelligence (MITRE correlation, behavioral baselines)
- ✅ Comprehensive Windows Defender security checks
- ✅ Compliance automation (CISA, NIST, CIS mappings)

**Roadmap:**
See `docs/ROADMAP.md` for detailed development phases and completed items.

### Contributing

1. Create a new module under `src/soc_audit/modules/`
2. Extend `BaseModule` and set a unique `name`
3. Implement `run(context: ModuleContext) -> ModuleResult`
4. Add configuration to `config/default.json`
5. The engine automatically discovers modules at runtime

### License

See LICENSE file for details.