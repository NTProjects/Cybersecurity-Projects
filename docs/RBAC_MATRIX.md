# RBAC (Role-Based Access Control) Matrix

**Phase 10.1: Enterprise RBAC Hardening**

This document defines the role-based access control matrix for the SOC Audit Framework.

## Roles

### Agent
- **Purpose:** Automated systems that send alerts and heartbeats
- **Level:** 0 (lowest)
- **Use Case:** Security agents, monitoring tools, automated scanners

### Analyst
- **Purpose:** Security analysts who investigate and respond to alerts
- **Level:** 1 (medium)
- **Use Case:** SOC analysts, incident responders, security operators

### Admin
- **Purpose:** Administrators with full system access
- **Level:** 2 (highest)
- **Use Case:** Security managers, system administrators, auditors

## Access Matrix

| Operation | Agent | Analyst | Admin | Notes |
|----------|-------|---------|-------|-------|
| **Read Operations** |
| `read_alerts` | ❌ Denied | ✅ Allowed | ✅ Allowed | List and view alerts |
| `read_incidents` | ❌ Denied | ✅ Allowed | ✅ Allowed | List and view incidents |
| `read_hosts` | ❌ Denied | ✅ Allowed | ✅ Allowed | List and view host registry |
| `view_metrics` | ❌ Denied | ✅ Allowed | ✅ Allowed | View incident metrics |
| `view_reports` | ❌ Denied | ✅ Allowed | ✅ Allowed | Export incident/host reports |
| **Write Operations** |
| `send_heartbeat` | ✅ Allowed | ❌ Denied | ✅ Allowed | Update host heartbeat |
| `ingest_alerts` | ❌ Denied | ✅ Allowed | ✅ Allowed | Ingest single alert event |
| `ingest_batch_alerts` | ✅ Allowed | ❌ Denied | ✅ Allowed | Ingest batch of alerts |
| `ack_alerts` | ❌ Denied | ✅ Allowed | ✅ Allowed | Acknowledge/unacknowledge alerts |
| `suppress_alerts` | ❌ Denied | ❌ Denied | ✅ Allowed | Suppress/unsuppress alerts (admin only) |
| `add_incident_notes` | ❌ Denied | ✅ Allowed | ✅ Allowed | Add notes to incidents |
| `close_incidents` | ❌ Denied | ❌ Denied | ✅ Allowed | Close incidents (admin only) |

## Explicit Deny Rules

### Agent Role
The following operations are **explicitly denied** for agents:
- `read_alerts`
- `read_incidents`
- `read_hosts`
- `ack_alerts`
- `suppress_alerts`
- `close_incidents`
- `view_reports`

### Analyst Role
The following operations are **explicitly denied** for analysts:
- `suppress_alerts` - Only admins can suppress alerts
- `close_incidents` - Only admins can close incidents

### Admin Role
No explicit deny rules (full access).

## Implementation Details

### Endpoint Protection

All API endpoints are protected using FastAPI dependencies:

```python
from soc_audit.server.rbac import require_analyst_or_admin, require_admin, require_agent_or_admin

@router.get("/alerts")
async def list_alerts(
    role: str = require_analyst_or_admin("read_alerts"),
    ...
):
    ...
```

### Role Hierarchy

Roles are checked using a hierarchy system:
- `agent`: Level 0
- `analyst`: Level 1
- `admin`: Level 2

A user with a higher-level role automatically has access to lower-level operations (unless explicitly denied).

### Explicit Deny Rules

Even if a role hierarchy check passes, explicit deny rules are enforced. This ensures that:
- Analysts cannot suppress alerts or close incidents (even though they have higher level than agent)
- Agents cannot read any data (even though they can write)

## Security Considerations

1. **Principle of Least Privilege:** Each role has the minimum permissions needed for their function.
2. **Explicit Deny:** Operations are explicitly denied rather than relying solely on hierarchy.
3. **Audit Trail:** All access attempts are logged (Phase 10.2).
4. **API Key Authentication:** All endpoints require valid API key authentication.

## Migration Notes

**Phase 10.1 Changes:**
- All endpoints now use consistent RBAC enforcement via dependencies
- Removed inconsistent try/except role checks
- Added explicit deny rules for analyst role
- Removed duplicate endpoint definitions

## Testing

To test RBAC enforcement:

```bash
# Test as agent (should fail on read operations)
curl -H "X-API-Key: AGENT_KEY" http://localhost:8001/api/v1/alerts

# Test as analyst (should succeed on read, fail on suppress)
curl -H "X-API-Key: ANALYST_KEY" http://localhost:8001/api/v1/alerts
curl -X POST -H "X-API-Key: ANALYST_KEY" http://localhost:8001/api/v1/alerts/{id}/suppress

# Test as admin (should succeed on all operations)
curl -H "X-API-Key: ADMIN_KEY" http://localhost:8001/api/v1/alerts
curl -X POST -H "X-API-Key: ADMIN_KEY" http://localhost:8001/api/v1/alerts/{id}/suppress
```
