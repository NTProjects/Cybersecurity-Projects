# SOC Audit Framework Roadmap

## Overview
This roadmap outlines the planned development phases for the SOC Audit Framework, focusing on enterprise hardening, real-time capabilities, detection intelligence, and operational excellence.

---

## 🔐 PHASE 10 — Enterprise Hardening (Foundation Phase)

**Goal:** Make the system safe, accountable, and enterprise-ready.

### 10.1 RBAC Hardening
- [ ] Enforce role checks per endpoint
- [ ] Explicit deny rules
- [ ] Role matrix documentation
- [ ] Remove "role awareness without enforcement"
- **Auditor value:** Access control verification (CISSP Domain 5)

### 10.2 Audit Logging (Critical)
- [ ] Immutable audit log:
  - [ ] who
  - [ ] what
  - [ ] when
  - [ ] where (endpoint / object)
- [ ] Stored separately from operational data
- [ ] Tamper-evident (hash chaining optional)
- **Auditor value:** Chain of custody, non-repudiation (CISA, ISO 27001)

### 10.3 Multi-User Readiness
- [ ] Concurrent analysts
- [ ] Session isolation
- [ ] Safe write operations
- **Auditor value:** Operational resilience

### 10.4 Observability
- [ ] Structured logs
- [ ] Error correlation IDs
- [ ] Performance instrumentation
- **Auditor value:** Incident response maturity

---

## 📡 PHASE 11 — Real-Time Without Polling

**Goal:** Safe real-time UX using push, not loops.

### 11.1 WebSocket Event Bus
- [ ] Push-only updates
- [ ] Explicit subscriptions
- [ ] Backpressure & rate limits

### 11.2 GUI Event Rehydration
- [ ] UI updates from events only
- [ ] Manual refresh remains available
- [ ] No auto-refresh loops
- **SOC value:** Live visibility without instability

---

## 🧠 PHASE 12 — Detection Intelligence

**Goal:** Elevate from alert viewer → detection platform.

### 12.1 MITRE ATT&CK Correlation Engine
- [ ] Technique chaining
- [ ] Kill-chain visualization
- [ ] Detection confidence scoring

### 12.2 Behavioral Baselines
- [ ] Host/entity baselining
- [ ] Deviation detection
- [ ] Risk amplification (RBA integration)
- **SOC value:** Reduced alert fatigue

---

## 🧱 PHASE 13 — Firewall & Network Security (BIG)

**Goal:** First-class network control & verification.

### 13.1 Firewall State Ingestion
- [ ] Windows Defender Firewall
- [ ] iptables / nftables
- [ ] Cloud SGs (later)

### 13.2 Firewall Configuration Viewer
- [ ] Rule parsing
- [ ] Human-readable diffs
- [ ] Policy intent mapping

### 13.3 Firewall Misconfiguration Detection
- [ ] Open ports vs exposure
- [ ] Shadow rules
- [ ] Insecure allow-alls
- **CISSP value:** Network security & access control

---

## 🔍 PHASE 14 — Compliance & Audit Automation

**Goal:** Turn SOC data into audit artifacts.

### 14.1 CISA Crosswalk Engine
- [ ] CISA Cross-Sector
- [ ] NIST 800-53
- [ ] CIS Controls v8

### 14.2 Evidence Auto-Collection
- [ ] "Show me proof" buttons
- [ ] Timestamped artifacts
- [ ] Exportable audit packets
- **Auditor value:** Reduced audit friction

---

## 🧪 PHASE 15 — Threat Hunting & Forensics

**Goal:** Analyst empowerment.

### 15.1 Threat Hunt Workspace
- [ ] Query historical events
- [ ] Timeline reconstruction
- [ ] Entity pivoting

### 15.2 Forensic Snapshots
- [ ] Host state capture
- [ ] Process / port snapshots
- [ ] Change tracking
- **SOC value:** Faster investigations

---

## 🧰 PHASE 16 — Active Response (Controlled)

**Goal:** Carefully allow action, not just visibility.

### 16.1 Response Playbooks
- [ ] Isolate host
- [ ] Block IP
- [ ] Kill process
- [ ] Disable account (future)

### 16.2 Approval Gates
- [ ] Analyst → Admin approval
- [ ] Full audit trail
- [ ] Dry-run mode
- **CISSP value:** Controlled response & accountability

---

## 🏗️ PHASE 17 — Enterprise & Scale

**Goal:** Prepare for real deployments.

### 17.1 Multi-Tenant Support
- [ ] Org / environment isolation
- [ ] Tenant-specific RBAC

### 17.2 HA & Storage Backends
- [ ] PostgreSQL
- [ ] External log stores
- [ ] Archival policies

---

## 🚀 PHASE 18 — SOC Command Platform

**Goal:** Become a true SOC console.

### 18.1 Unified Security Dashboard
- [ ] Network + host + identity
- [ ] Risk posture score
- [ ] Executive view

### 18.2 Analyst & Auditor Modes
- [ ] SOC view
- [ ] Audit-only read mode
- [ ] Evidence export mode

### 18.3 External Integrations
- [ ] SIEM export
- [ ] SOAR hooks
- [ ] Ticketing systems
