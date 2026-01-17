"""Test script for Phase 10.2 Audit Logging.

Tests:
1. Audit logger creates entries
2. Hash chaining works
3. Chain verification works
4. Query functionality works
"""
import sys
import tempfile
from pathlib import Path
from datetime import datetime, timedelta

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))


def test_audit_logger_basic():
    """Test basic audit logging functionality."""
    from soc_audit.server.audit_log import AuditLogger
    
    # Use temporary database
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    
    try:
        logger = AuditLogger(db_path)
        
        # Log some entries
        entry_id_1 = logger.log(
            user_id="user123",
            role="analyst",
            operation="read_alerts",
            action="read",
            result="success",
            endpoint="/api/v1/alerts",
            object_type="alert",
        )
        
        entry_id_2 = logger.log(
            user_id="user123",
            role="analyst",
            operation="ack_alert",
            action="update",
            result="success",
            endpoint="/api/v1/alerts/alert-123/ack",
            object_type="alert",
            object_id="alert-123",
        )
        
        assert entry_id_1 > 0
        assert entry_id_2 > entry_id_1
        
        print("[PASS] Basic audit logging works")
        
        # Test query
        entries = logger.query(role="analyst", limit=10)
        assert len(entries) >= 2
        assert entries[0]["operation"] == "ack_alert"  # Most recent first
        assert entries[1]["operation"] == "read_alerts"
        
        print("[PASS] Query functionality works")
        
        # Test chain verification
        is_valid, errors = logger.verify_chain()
        assert is_valid, f"Chain verification failed: {errors}"
        
        print("[PASS] Chain verification works")
        
        logger.close()
        
    finally:
        # Cleanup
        Path(db_path).unlink(missing_ok=True)


def test_hash_chaining():
    """Test hash chaining integrity."""
    from soc_audit.server.audit_log import AuditLogger
    
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    
    try:
        logger = AuditLogger(db_path)
        
        # Create chain of entries
        for i in range(5):
            logger.log(
                user_id=f"user{i}",
                role="analyst",
                operation=f"operation_{i}",
                action="read",
                result="success",
            )
        
        # Verify chain
        is_valid, errors = logger.verify_chain()
        assert is_valid, f"Chain verification failed: {errors}"
        
        # Query entries
        entries = logger.query(limit=10)
        assert len(entries) == 5
        
        # Check that previous_hash chains correctly
        for i in range(1, len(entries)):
            prev_entry = entries[i]  # Older entry
            curr_entry = entries[i - 1]  # Newer entry
            assert curr_entry["previous_hash"] == prev_entry["entry_hash"]
        
        print("[PASS] Hash chaining integrity verified")
        
        logger.close()
        
    finally:
        Path(db_path).unlink(missing_ok=True)


def main():
    """Run all tests."""
    print("=" * 60)
    print("Phase 10.2 Audit Logging - Test Suite")
    print("=" * 60)
    print()
    
    try:
        test_audit_logger_basic()
        test_hash_chaining()
        
        print()
        print("=" * 60)
        print("[PASS] All Phase 10.2 Audit Logging tests passed")
        print("=" * 60)
        return 0
    except Exception as e:
        print(f"[FAIL] Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
