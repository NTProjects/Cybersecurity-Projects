"""Structured logging configuration for SOC Audit Server.

Phase 10.4: Observability
- Structured logs (JSON format)
- Error correlation IDs
- Performance instrumentation
"""
from __future__ import annotations

import json
import logging
import sys
import time
import uuid
from contextvars import ContextVar
from datetime import datetime
from typing import Any

# Context variable for request correlation ID
correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)


def get_correlation_id() -> str:
    """Get current correlation ID or generate a new one."""
    corr_id = correlation_id_var.get()
    if not corr_id:
        corr_id = str(uuid.uuid4())[:8]
        correlation_id_var.set(corr_id)
    return corr_id


def set_correlation_id(corr_id: str) -> None:
    """Set correlation ID for current context."""
    correlation_id_var.set(corr_id)


class StructuredFormatter(logging.Formatter):
    """
    Structured JSON formatter for logs.
    
    Phase 10.4: Outputs logs as JSON for better observability and parsing.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": get_correlation_id(),
            "module": record.module if hasattr(record, "module") else None,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)
        
        # Add performance metrics if present
        if hasattr(record, "duration_ms"):
            log_data["duration_ms"] = record.duration_ms
        
        if hasattr(record, "operation"):
            log_data["operation"] = record.operation
        
        return json.dumps(log_data)


def setup_logging(
    level: str = "INFO",
    use_json: bool = True,
    include_correlation: bool = True,
) -> None:
    """
    Configure structured logging for the application.
    
    Phase 10.4: Sets up JSON-formatted structured logging with correlation IDs.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        use_json: Whether to use JSON formatting (default: True).
        include_correlation: Whether to include correlation IDs (default: True).
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    # Set formatter
    if use_json:
        formatter = StructuredFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(correlation_id)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)


class PerformanceLogger:
    """
    Performance instrumentation logger.
    
    Phase 10.4: Tracks operation durations and performance metrics.
    """
    
    def __init__(self, logger: logging.Logger, operation: str):
        """
        Initialize performance logger.
        
        Args:
            logger: Python logger instance.
            operation: Operation name being tracked.
        """
        self.logger = logger
        self.operation = operation
        self.start_time: float | None = None
    
    def __enter__(self) -> PerformanceLogger:
        """Start timing."""
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type: type | None, exc_val: Exception | None, exc_tb: Any) -> None:
        """End timing and log performance metrics."""
        if self.start_time:
            duration_ms = (time.perf_counter() - self.start_time) * 1000
            
            # Create log record with performance data
            record = logging.LogRecord(
                name=self.logger.name,
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg=f"Operation '{self.operation}' completed",
                args=(),
                exc_info=None,
            )
            record.operation = self.operation
            record.duration_ms = duration_ms
            record.correlation_id = get_correlation_id()
            
            if exc_type:
                record.levelno = logging.ERROR
                record.levelname = "ERROR"
                record.msg = f"Operation '{self.operation}' failed"
                record.exc_info = (exc_type, exc_val, exc_tb)
            
            self.logger.handle(record)


def log_performance(operation: str, logger: logging.Logger | None = None) -> PerformanceLogger:
    """
    Context manager for performance logging.
    
    Phase 10.4: Decorator for tracking operation performance.
    
    Usage:
        with log_performance("save_alert", logger):
            # ... operation code ...
    
    Args:
        operation: Operation name to track.
        logger: Logger instance (defaults to caller's module logger).
    
    Returns:
        PerformanceLogger context manager.
    """
    if logger is None:
        import inspect
        frame = inspect.currentframe()
        if frame and frame.f_back:
            caller_module = frame.f_back.f_globals.get("__name__", "unknown")
            logger = logging.getLogger(caller_module)
    
    return PerformanceLogger(logger, operation)


def add_extra_fields(extra_fields: dict[str, Any]) -> logging.LoggerAdapter:
    """
    Add extra fields to log records.
    
    Phase 10.4: Utility to add context fields to logs.
    
    Args:
        extra_fields: Dictionary of extra fields to include in logs.
    
    Returns:
        LoggerAdapter with extra fields.
    """
    logger = logging.getLogger()
    
    class ExtraFieldsAdapter(logging.LoggerAdapter):
        def process(self, msg: Any, kwargs: Any) -> tuple[Any, dict[str, Any]]:
            kwargs.setdefault("extra", {})["extra_fields"] = extra_fields
            return msg, kwargs
    
    return ExtraFieldsAdapter(logger, {})
