"""Job handlers for the tests. Worker processes import this module by name, so the tests put
its directory on ``sys.path`` (pytest imports test files by path, not as a package)."""

from __future__ import annotations

import os
import time
from typing import Any

from kasauti.jobs import JobError
from kasauti.jobs.pool import worker_secret

LEAKED_LINE = "enable secret 5 $1$PLACEHOLDER$leaked"

HANDLERS = {
    "echo": "job_handlers:echo",
    "refuse": "job_handlers:refuse",
    "leak": "job_handlers:leak",
    "crash": "job_handlers:crash",
    "sleep": "job_handlers:sleep",
    "huge": "job_handlers:huge",
    "hog": "job_handlers:hog",
    "secret": "job_handlers:secret",
    "not_json": "job_handlers:not_json",
    "not_object": "job_handlers:not_object",
}


def echo(payload: dict[str, Any]) -> dict[str, Any]:
    return {"echo": payload, "pid": os.getpid()}


def refuse(_payload: dict[str, Any]) -> dict[str, Any]:
    raise JobError("not a configuration file")


def leak(_payload: dict[str, Any]) -> dict[str, Any]:
    # A parser error quoting the line it choked on: the text must not reach the job row.
    raise ValueError(f"can't parse {LEAKED_LINE!r}")


def crash(_payload: dict[str, Any]) -> dict[str, Any]:
    os._exit(3)


def sleep(payload: dict[str, Any]) -> dict[str, Any]:
    time.sleep(payload["s"])
    return {"slept": payload["s"]}


def huge(payload: dict[str, Any]) -> dict[str, Any]:
    """``2n`` characters: random hex, which gzip can only halve, or with ``plain`` one letter
    repeated, which it shrinks a thousandfold."""
    n = payload["n"]
    return {"x": "a" * 2 * n if payload.get("plain") else os.urandom(n).hex()}


def secret(_payload: dict[str, Any]) -> dict[str, Any]:
    """Whether the pool handed this process the test secret."""
    return {"seen": worker_secret("test") == b"\x00sealing key\xff"}


def hog(payload: dict[str, Any]) -> dict[str, Any]:
    """Asks for ``mib`` MiB at once, and touches it."""
    block = bytearray(payload["mib"] * 1024 * 1024)
    block[-1] = 1
    return {"got": len(block)}


def not_json(_payload: dict[str, Any]) -> dict[str, Any]:
    return {"x": {1, 2}}


def not_object(_payload: dict[str, Any]) -> Any:
    return [1, 2]
