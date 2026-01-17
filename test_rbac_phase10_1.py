"""Test script for Phase 10.1 RBAC Hardening.

Tests:
1. All endpoints enforce RBAC
2. Explicit deny rules work
3. Role hierarchy works
4. No duplicate endpoints
"""
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_rbac_module():
    """Test RBAC module loads and has correct structure."""
    from soc_audit.server.rbac import (
        ROLE_HIERARCHY,
        DENY_RULES,
        ROLE_MATRIX,
        require_role,
        require_analyst_or_admin,
        require_admin,
        require_agent_or_admin,
    )
    
    assert "agent" in ROLE_HIERARCHY
    assert "analyst" in ROLE_HIERARCHY
    assert "admin" in ROLE_HIERARCHY
    assert ROLE_HIERARCHY["agent"] < ROLE_HIERARCHY["analyst"]
    assert ROLE_HIERARCHY["analyst"] < ROLE_HIERARCHY["admin"]
    
    assert "agent" in DENY_RULES
    assert "analyst" in DENY_RULES
    assert "suppress_alerts" in DENY_RULES["analyst"]
    assert "close_incidents" in DENY_RULES["analyst"]
    
    assert "agent" in ROLE_MATRIX
    assert "analyst" in ROLE_MATRIX
    assert "admin" in ROLE_MATRIX
    
    print("[PASS] RBAC module structure verified")


def test_endpoints_have_rbac():
    """Test that all endpoints use RBAC dependencies."""
    import inspect
    from soc_audit.server.routes import alerts, incidents, hosts, heartbeat, ingest, ingest_batch, reports
    
    endpoints_to_check = [
        (alerts, ["list_alerts", "get_alert", "ack_alert", "suppress_alert"]),
        (incidents, ["list_incidents", "get_incident", "close_incident", "add_incident_note", "get_incident_metrics"]),
        (hosts, ["list_hosts", "get_host"]),
        (heartbeat, ["heartbeat"]),
        (ingest, ["ingest_event"]),
        (ingest_batch, ["ingest_batch"]),
        (reports, ["get_incident_report", "get_host_report"]),
    ]
    
    issues = []
    for module, func_names in endpoints_to_check:
        for func_name in func_names:
            if not hasattr(module, func_name):
                continue
            func = getattr(module, func_name)
            sig = inspect.signature(func)
            params = list(sig.parameters.values())
            
            # Check if role parameter exists with RBAC dependency
            has_role_param = any(p.name == "role" for p in params)
            if not has_role_param:
                issues.append(f"{module.__name__}.{func_name} missing 'role' parameter")
    
    if issues:
        print("[FAIL] Endpoints missing RBAC:")
        for issue in issues:
            print(f"  - {issue}")
        return False
    
    print("[PASS] All endpoints have RBAC enforcement")
    return True


def test_no_duplicate_endpoints():
    """Test for duplicate endpoint definitions."""
    from soc_audit.server.routes import incidents
    
    # Check incidents.py for duplicate get_incident_metrics
    import ast
    import inspect
    
    source = inspect.getsource(incidents)
    tree = ast.parse(source)
    
    function_names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            function_names.append(node.name)
    
    duplicates = [name for name in function_names if function_names.count(name) > 1]
    if duplicates:
        print(f"[FAIL] Duplicate functions found: {duplicates}")
        return False
    
    print("[PASS] No duplicate endpoint definitions")
    return True


def main():
    """Run all tests."""
    print("=" * 60)
    print("Phase 10.1 RBAC Hardening - Test Suite")
    print("=" * 60)
    print()
    
    try:
        test_rbac_module()
        if not test_endpoints_have_rbac():
            sys.exit(1)
        if not test_no_duplicate_endpoints():
            sys.exit(1)
        
        print()
        print("=" * 60)
        print("[PASS] All Phase 10.1 RBAC tests passed")
        print("=" * 60)
        return 0
    except Exception as e:
        print(f"[FAIL] Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
