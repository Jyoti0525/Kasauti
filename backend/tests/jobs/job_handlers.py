"""Job handlers for the tests. Worker processes import this module by name, so the tests put
its directory on ``sys.path`` (pytest imports test files by path, not as a package)."""

from __future__ import annotations

import os
import time
from typing import Any

from kasauti.jobs import JobError
from kasauti.jobs.table import RESULT_LIMIT

LEAKED_LINE = "enable secret 5 $1$PLACEHOLDER$leaked"

HANDLERS = {
    "echo": "job_handlers:echo",
    "refuse": "job_handlers:refuse",
    "leak": "job_handlers:leak",
    "crash": "job_handlers:crash",
    "sleep": "job_handlers:sleep",
    "huge": "job_handlers:huge",
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


def huge(_payload: dict[str, Any]) -> dict[str, Any]:
    return {"x": "a" * (RESULT_LIMIT + 10)}


def not_json(_payload: dict[str, Any]) -> dict[str, Any]:
    return {"x": {1, 2}}


def not_object(_payload: dict[str, Any]) -> Any:
    return [1, 2]
