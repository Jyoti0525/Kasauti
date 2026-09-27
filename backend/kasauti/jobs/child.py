"""The worker process's side of a job (PLAN §4.2; TODO M2.03): everything a worker imports
before it runs its handler, and nothing more.

A worker never sees the database, so this module and what it imports stay clear of it: each
job starts a fresh process (:mod:`kasauti.jobs.pool`), and importing SQLAlchemy and Alembic
there cost about 0.4 s a job for nothing (M2.09).
"""

from __future__ import annotations

import importlib
import json
import re
import signal
from collections.abc import Callable, Mapping
from multiprocessing.connection import Connection
from typing import Any

from kasauti.jobs.limits import limit_memory
from kasauti.jobs.results import encode_result

type JsonObject = dict[str, Any]
type Handler = Callable[[JsonObject], JsonObject]

ERROR_LIMIT = 500
"""Characters of the error shown for a failed job."""
_TARGET = re.compile(r"[A-Za-z_][\w.]*:[A-Za-z_]\w*")
_SECRETS: dict[str, bytes] = {}
"""In a worker process: what the pool handed it at start (see :func:`worker_secret`)."""


class JobError(Exception):
    """Raised by a handler for a failure the user should read, e.g. "not a configuration file".
    The message is stored and shown as is, so it must never quote the input."""


def canonical(obj: JsonObject) -> str:
    """One JSON text per value: sorted keys, no whitespace, no NaN or infinity."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def worker_secret(name: str) -> bytes | None:
    """A secret the pool handed this worker process when it started, such as the key staged
    uploads are sealed with. Secrets travel over the pipe that starts the process: never
    through the database, never in a payload, so a job row can't reveal them."""
    return _SECRETS.get(name)


def set_worker_secrets(secrets: Mapping[str, bytes]) -> None:
    """Hand this process its secrets: done by the pool in each worker; tests running a handler
    in their own process do it themselves."""
    _SECRETS.clear()
    _SECRETS.update(secrets)


def resolve(target: str) -> Handler:
    """``"package.module:function"`` to the function. Targets come from the code's own
    registry (``kasauti.jobs.kinds``), never from a request or the database."""
    if not _TARGET.fullmatch(target):
        raise ValueError(f"handler target {target!r} isn't 'module:function'")
    module, _, name = target.partition(":")
    handler = getattr(importlib.import_module(module), name, None)
    if not callable(handler):
        raise TypeError(f"handler target {target!r} isn't a function")
    return handler  # type: ignore[no-any-return]


def run(
    conn: Connection, target: str, payload: str, memory_mib: int, secrets: Mapping[str, bytes]
) -> None:
    """A worker process's whole life: cap its memory, run one job, send one message, exit."""
    # Ctrl+C in a console reaches every process in it; stopping jobs is the pool's decision.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    set_worker_secrets(secrets)
    try:
        limit_memory(memory_mib)
        result: object = resolve(target)(json.loads(payload))  # a handler may break its type
        if not isinstance(result, dict):
            data = failure("the job returned something other than an object")
        else:
            data = encode_result(result)
    except JobError as err:
        data = failure(str(err))
    except MemoryError:
        # What the job built is released as the exception unwinds, so there is room to answer.
        data = failure(f"it needed more than the {memory_mib} MiB of memory a worker may use")
    except BaseException as err:  # anything the handler raises is reported
        # Including a result that isn't JSON (TypeError or ValueError from encode_result()).
        data = canonical({"exception": type(err).__name__}).encode()
    try:
        conn.send_bytes(data)
    finally:
        conn.close()


def failure(error: str) -> bytes:
    return canonical({"error": error[:ERROR_LIMIT]}).encode()
