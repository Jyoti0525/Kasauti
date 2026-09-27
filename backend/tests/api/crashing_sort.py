"""A sort handler for the tests: the real one, except that its worker process dies, as a
hostile file might make it, when a file holds :data:`MARKER`. Worker processes import it by
name, so the test puts this directory on ``sys.path``, which spawned processes inherit."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from kasauti.ingest.sort import _read, sort_files
from kasauti.ingest.staging import STAGING_KEY_NAME
from kasauti.jobs.child import worker_secret

MARKER = b"! crash the worker"


def sort_or_crash(payload: dict[str, Any]) -> dict[str, Any]:
    key = worker_secret(STAGING_KEY_NAME)
    assert key is not None
    for file_id in payload["files"]:
        if MARKER in _read(Path(payload["staging"]), key, payload["upload"], file_id):
            os._exit(3)
    return sort_files(payload)
