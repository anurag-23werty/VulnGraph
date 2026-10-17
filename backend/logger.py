"""
Structured JSON Logger with Request Tracing for VulnGraph.
==========================================================
Formats all application and security events into standardized JSON logs.
Supports per-request correlation via contextvars (request_id).
"""

import json
import logging
import sys
import contextvars
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Context variable for request correlation
request_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("request_id", default=None)


class JSONFormatter(logging.Formatter):
    """Formats log records as JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        log_payload: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_ctx.get(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }

        # Include custom attributes from record
        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            log_payload.update(record.extra_data)

        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_payload)


def setup_logger(name: str = "vulngraph", level: int = logging.INFO) -> logging.Logger:
    """Configures and returns a structured JSON logger."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers if already configured
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.propagate = False

    return logger


# Global application logger instance
logger = setup_logger("vulngraph")
