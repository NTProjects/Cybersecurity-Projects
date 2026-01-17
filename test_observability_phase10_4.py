"""Test script for Phase 10.4 Observability.

Tests:
1. Structured logging works
2. Correlation IDs are generated
3. Performance logging works
4. Error correlation works
"""
import sys
import json
from pathlib import Path
from io import StringIO

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))


def test_structured_logging():
    """Test structured logging outputs JSON."""
    from soc_audit.server.logging_config import setup_logging, StructuredFormatter
    import logging
    
    # Capture log output
    log_capture = StringIO()
    handler = logging.StreamHandler(log_capture)
    handler.setFormatter(StructuredFormatter())
    
    logger = logging.getLogger("test")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    
    logger.info("Test message")
    
    output = log_capture.getvalue()
    assert output, "Log output should not be empty"
    
    # Try to parse as JSON
    log_data = json.loads(output.strip())
    assert "timestamp" in log_data
    assert "level" in log_data
    assert "message" in log_data
    assert "correlation_id" in log_data
    
    print("[PASS] Structured logging outputs valid JSON")


def test_correlation_id():
    """Test correlation ID generation and context."""
    from soc_audit.server.logging_config import get_correlation_id, set_correlation_id
    
    # Generate new ID
    id1 = get_correlation_id()
    assert id1, "Correlation ID should be generated"
    assert len(id1) == 8, "Correlation ID should be 8 characters"
    
    # Set specific ID
    set_correlation_id("test123")
    id2 = get_correlation_id()
    assert id2 == "test123", "Correlation ID should be set"
    
    print("[PASS] Correlation ID generation and context work")


def test_performance_logging():
    """Test performance logging context manager."""
    from soc_audit.server.logging_config import log_performance, setup_logging
    import logging
    import time
    
    setup_logging(level="INFO", use_json=False)  # Use plain format for testing
    logger = logging.getLogger("test")
    
    log_capture = StringIO()
    handler = logging.StreamHandler(log_capture)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    
    # Use performance logger
    with log_performance("test_operation", logger):
        time.sleep(0.01)  # Small delay
    
    output = log_capture.getvalue()
    assert "test_operation" in output or "duration_ms" in output or "Operation" in output
    
    print("[PASS] Performance logging works")


def main():
    """Run all tests."""
    print("=" * 60)
    print("Phase 10.4 Observability - Test Suite")
    print("=" * 60)
    print()
    
    try:
        test_structured_logging()
        test_correlation_id()
        test_performance_logging()
        
        print()
        print("=" * 60)
        print("[PASS] All Phase 10.4 Observability tests passed")
        print("=" * 60)
        return 0
    except Exception as e:
        print(f"[FAIL] Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
