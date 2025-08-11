
"""
CRO AI Agent - Structured Logging Configuration
===============================================

Structured logging setup using structlog with JSON formatting,
file rotation, different log levels, and observability integration.
"""

import logging
import logging.handlers
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import structlog
from structlog.types import EventDict, Processor
from pythonjsonlogger import jsonlogger

from app.core.config import get_settings, get_observability_settings

# Get settings
settings = get_settings()
obs_settings = get_observability_settings()

# Constants
LOG_RECORD_BUILTIN_ATTRS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
    "taskName",
}

# Sensitive fields to sanitize
SENSITIVE_FIELDS = {
    "password",
    "token",
    "secret",
    "key",
    "authorization",
    "cookie",
    "session",
    "api_key",
    "access_token",
    "refresh_token",
    "jwt",
    "bearer",
    "credentials",
    "auth",
    "private_key",
    "client_secret",
}


def sanitize_sensitive_data(data: Any) -> Any:
    """
    Recursively sanitize sensitive data from log entries.
    
    Args:
        data: Data to sanitize
        
    Returns:
        Sanitized data with sensitive fields masked
    """
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            key_lower = str(key).lower()
            
            # Check if key contains sensitive information
            is_sensitive = any(sensitive in key_lower for sensitive in SENSITIVE_FIELDS)
            
            if is_sensitive:
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = sanitize_sensitive_data(value)
        
        return sanitized
    
    elif isinstance(data, (list, tuple)):
        return [sanitize_sensitive_data(item) for item in data]
    
    elif isinstance(data, str):
        # Check for common patterns in strings
        data_lower = data.lower()
        if any(sensitive in data_lower for sensitive in SENSITIVE_FIELDS):
            # If it looks like a token/key (long alphanumeric string)
            if len(data) > 20 and data.replace("-", "").replace("_", "").isalnum():
                return "***REDACTED***"
        return data
    
    else:
        return data


def add_timestamp(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Add timestamp to log entry."""
    event_dict["timestamp"] = time.time()
    event_dict["iso_timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime())
    return event_dict


def add_log_level(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Add log level to event dict."""
    event_dict["level"] = method_name.upper()
    return event_dict


def add_logger_name(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Add logger name to event dict."""
    event_dict["logger"] = logger.name
    return event_dict


def add_process_info(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Add process information to log entry."""
    event_dict["process_id"] = os.getpid()
    event_dict["thread_id"] = structlog.get_context().get("thread_id")
    return event_dict


def add_application_context(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Add application context to log entry."""
    event_dict["service"] = settings.APP_NAME
    event_dict["version"] = settings.APP_VERSION
    event_dict["environment"] = settings.ENVIRONMENT
    return event_dict


def add_trace_context(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Add tracing context to log entry."""
    try:
        from opentelemetry import trace
        
        span = trace.get_current_span()
        if span and span.is_recording():
            span_context = span.get_span_context()
            event_dict["trace_id"] = format(span_context.trace_id, "032x")
            event_dict["span_id"] = format(span_context.span_id, "016x")
    except ImportError:
        pass
    except Exception:
        # Don't fail logging if tracing fails
        pass
    
    return event_dict


def sanitize_event_dict(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Sanitize sensitive data from event dict."""
    return sanitize_sensitive_data(event_dict)


def filter_by_level(record: logging.LogRecord) -> bool:
    """Filter log records by level."""
    return record.levelno >= getattr(logging, settings.LOG_LEVEL.upper())


class JSONFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter for structured logging."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]):
        """Add custom fields to log record."""
        super().add_fields(log_record, record, message_dict)
        
        # Add standard fields
        log_record["timestamp"] = time.time()
        log_record["iso_timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime())
        log_record["level"] = record.levelname
        log_record["logger"] = record.name
        log_record["service"] = settings.APP_NAME
        log_record["version"] = settings.APP_VERSION
        log_record["environment"] = settings.ENVIRONMENT
        
        # Add process info
        log_record["process_id"] = os.getpid()
        
        # Add file info
        log_record["file"] = record.filename
        log_record["line"] = record.lineno
        log_record["function"] = record.funcName
        
        # Sanitize sensitive data
        log_record = sanitize_sensitive_data(log_record)


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output in development."""
    
    # Color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m',       # Reset
    }
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        if not settings.DEBUG:
            return super().format(record)
        
        # Add color to level name
        level_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{level_color}{record.levelname}{self.COLORS['RESET']}"
        
        return super().format(record)


def setup_file_handler() -> Optional[logging.Handler]:
    """Setup file handler with rotation."""
    if not obs_settings.LOG_FILE_PATH:
        return None
    
    # Create log directory if it doesn't exist
    log_file = Path(obs_settings.LOG_FILE_PATH)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Setup rotating file handler
    if obs_settings.LOG_ROTATION == "size":
        handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=10,
            encoding="utf-8",
        )
    else:
        # Time-based rotation
        handler = logging.handlers.TimedRotatingFileHandler(
            filename=log_file,
            when="midnight",
            interval=1,
            backupCount=int(obs_settings.LOG_RETENTION.split()[0]),
            encoding="utf-8",
        )
    
    # Set formatter based on log format
    if obs_settings.LOG_FORMAT == "json":
        formatter = JSONFormatter(
            fmt="%(timestamp)s %(level)s %(logger)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    
    handler.setFormatter(formatter)
    handler.addFilter(filter_by_level)
    
    return handler


def setup_console_handler() -> logging.Handler:
    """Setup console handler."""
    handler = logging.StreamHandler(sys.stdout)
    
    if settings.DEBUG and obs_settings.LOG_FORMAT != "json":
        # Use colored formatter for development
        formatter = ColoredFormatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%H:%M:%S",
        )
    elif obs_settings.LOG_FORMAT == "json":
        # Use JSON formatter
        formatter = JSONFormatter(
            fmt="%(timestamp)s %(level)s %(logger)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    else:
        # Use standard formatter
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    
    handler.setFormatter(formatter)
    handler.addFilter(filter_by_level)
    
    return handler


def setup_structlog_processors() -> List[Processor]:
    """Setup structlog processors."""
    processors = [
        # Add context
        add_timestamp,
        add_log_level,
        add_logger_name,
        add_process_info,
        add_application_context,
        add_trace_context,
        
        # Sanitize sensitive data
        sanitize_event_dict,
        
        # Standard processors
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
    ]
    
    if settings.DEBUG:
        processors.extend([
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.set_exc_info,
        ])
    
    # Add final processor based on format
    if obs_settings.LOG_FORMAT == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        if settings.DEBUG:
            processors.append(structlog.dev.ConsoleRenderer(colors=True))
        else:
            processors.append(structlog.processors.KeyValueRenderer())
    
    return processors


def setup_standard_logging():
    """Setup standard Python logging."""
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Add console handler
    console_handler = setup_console_handler()
    root_logger.addHandler(console_handler)
    
    # Add file handler if configured
    file_handler = setup_file_handler()
    if file_handler:
        root_logger.addHandler(file_handler)
    
    # Configure specific loggers
    configure_third_party_loggers()


def configure_third_party_loggers():
    """Configure third-party library loggers."""
    # Reduce noise from third-party libraries
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("fastapi").setLevel(logging.INFO)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(logging.WARNING)
    
    # Set specific levels based on environment
    if settings.ENVIRONMENT == "production":
        logging.getLogger("asyncio").setLevel(logging.WARNING)
        logging.getLogger("concurrent.futures").setLevel(logging.WARNING)
    
    # Enable SQL query logging in development if requested
    if settings.DEBUG and settings.development.SHOW_SQL_QUERIES:
        logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO)


def setup_logging():
    """Setup complete logging configuration."""
    # Setup standard logging first
    setup_standard_logging()
    
    # Configure structlog
    structlog.configure(
        processors=setup_structlog_processors(),
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.LOG_LEVEL.upper())
        ),
        logger_factory=structlog.WriteLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Log startup message
    logger = structlog.get_logger(__name__)
    logger.info(
        "Logging system initialized",
        log_level=settings.LOG_LEVEL,
        log_format=obs_settings.LOG_FORMAT,
        log_file=obs_settings.LOG_FILE_PATH,
        environment=settings.ENVIRONMENT,
    )


def get_logger(name: str) -> structlog.BoundLogger:
    """
    Get a structured logger instance.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Configured structlog logger
    """
    return structlog.get_logger(name)


def log_function_call(func_name: str, args: tuple = None, kwargs: dict = None):
    """
    Decorator to log function calls.
    
    Args:
        func_name: Function name
        args: Function arguments
        kwargs: Function keyword arguments
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            logger = get_logger(func.__module__)
            
            # Sanitize arguments
            safe_args = sanitize_sensitive_data(args) if args else None
            safe_kwargs = sanitize_sensitive_data(kwargs) if kwargs else None
            
            logger.debug(
                f"Calling function: {func_name}",
                function=func_name,
                args=safe_args,
                kwargs=safe_kwargs,
            )
            
            try:
                result = func(*args, **kwargs)
                logger.debug(
                    f"Function completed: {func_name}",
                    function=func_name,
                    success=True,
                )
                return result
            
            except Exception as e:
                logger.error(
                    f"Function failed: {func_name}",
                    function=func_name,
                    error=str(e),
                    error_type=type(e).__name__,
                    success=False,
                )
                raise
        
        return wrapper
    return decorator


def log_async_function_call(func_name: str):
    """
    Decorator to log async function calls.
    
    Args:
        func_name: Function name
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            logger = get_logger(func.__module__)
            
            # Sanitize arguments
            safe_args = sanitize_sensitive_data(args) if args else None
            safe_kwargs = sanitize_sensitive_data(kwargs) if kwargs else None
            
            logger.debug(
                f"Calling async function: {func_name}",
                function=func_name,
                args=safe_args,
                kwargs=safe_kwargs,
            )
            
            try:
                result = await func(*args, **kwargs)
                logger.debug(
                    f"Async function completed: {func_name}",
                    function=func_name,
                    success=True,
                )
                return result
            
            except Exception as e:
                logger.error(
                    f"Async function failed: {func_name}",
                    function=func_name,
                    error=str(e),
                    error_type=type(e).__name__,
                    success=False,
                )
                raise
        
        return wrapper
    return decorator


class LogContext:
    """Context manager for adding context to logs."""
    
    def __init__(self, **context):
        self.context = context
        self.token = None
    
    def __enter__(self):
        self.token = structlog.contextvars.bind_contextvars(**self.context)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.token:
            structlog.contextvars.unbind_contextvars(self.token)


def with_log_context(**context):
    """
    Decorator to add context to all logs within a function.
    
    Args:
        **context: Context variables to add
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            with LogContext(**context):
                return func(*args, **kwargs)
        return wrapper
    return decorator


def with_async_log_context(**context):
    """
    Decorator to add context to all logs within an async function.
    
    Args:
        **context: Context variables to add
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            with LogContext(**context):
                return await func(*args, **kwargs)
        return wrapper
    return decorator


# Performance monitoring
class PerformanceLogger:
    """Logger for performance monitoring."""
    
    def __init__(self, name: str):
        self.logger = get_logger(name)
        self.start_time = None
    
    def start(self, operation: str, **context):
        """Start timing an operation."""
        self.start_time = time.time()
        self.operation = operation
        self.context = context
        
        self.logger.debug(
            f"Starting operation: {operation}",
            operation=operation,
            **context
        )
    
    def end(self, success: bool = True, **additional_context):
        """End timing an operation."""
        if self.start_time is None:
            return
        
        duration = time.time() - self.start_time
        
        log_data = {
            "operation": self.operation,
            "duration_seconds": duration,
            "success": success,
            **self.context,
            **additional_context,
        }
        
        if success:
            self.logger.info(
                f"Operation completed: {self.operation}",
                **log_data
            )
        else:
            self.logger.warning(
                f"Operation failed: {self.operation}",
                **log_data
            )
        
        self.start_time = None


def performance_monitor(operation_name: str):
    """
    Decorator for monitoring function performance.
    
    Args:
        operation_name: Name of the operation being monitored
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            perf_logger = PerformanceLogger(func.__module__)
            perf_logger.start(operation_name, function=func.__name__)
            
            try:
                result = func(*args, **kwargs)
                perf_logger.end(success=True)
                return result
            except Exception as e:
                perf_logger.end(success=False, error=str(e))
                raise
        
        return wrapper
    return decorator


def async_performance_monitor(operation_name: str):
    """
    Decorator for monitoring async function performance.
    
    Args:
        operation_name: Name of the operation being monitored
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            perf_logger = PerformanceLogger(func.__module__)
            perf_logger.start(operation_name, function=func.__name__)
            
            try:
                result = await func(*args, **kwargs)
                perf_logger.end(success=True)
                return result
            except Exception as e:
                perf_logger.end(success=False, error=str(e))
                raise
        
        return wrapper
    return decorator


# Export commonly used items
__all__ = [
    "setup_logging",
    "get_logger",
    "log_function_call",
    "log_async_function_call",
    "LogContext",
    "with_log_context",
    "with_async_log_context",
    "PerformanceLogger",
    "performance_monitor",
    "async_performance_monitor",
    "sanitize_sensitive_data",
]
