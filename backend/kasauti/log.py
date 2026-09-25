"""Structured logging with secret redaction (PLAN §17).

Configs contain passwords, keys and SNMP communities. Log events must never carry them, so a
processor masks any field whose name looks secret before anything is rendered.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog

_SECRET_KEY = re.compile(
    r"pass(word)?|secret|community|psk|pre[-_]?shared|token|credential|key$", re.I
)
REDACTED = "****"


def redact_secrets(
    _logger: Any, _method: str, event: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    for name in list(event):
        if name != "event" and _SECRET_KEY.search(name):
            event[name] = REDACTED
    return event


def configure(*, json: bool = False, level: int = logging.INFO) -> None:
    """Call once at process start (API server, CLI, worker)."""
    renderer: Any = structlog.processors.JSONRenderer() if json else structlog.dev.ConsoleRenderer()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            redact_secrets,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> Any:
    return structlog.get_logger(name)
