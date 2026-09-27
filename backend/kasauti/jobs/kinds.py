"""The job kinds Kasauti runs, and the function that runs each (``"module:function"``).

This mapping is the only way to name code a worker runs: a job row holds a kind, never a
module or function, so nothing in the database or a request can choose what executes.

A handler takes the job's payload (a JSON object of references and options, never
configuration text) and returns a JSON object. It raises :class:`kasauti.jobs.JobError` with a
message fit to show the user; anything else it raises is recorded by type only.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

HANDLERS: Mapping[str, str] = MappingProxyType(
    {
        "audit_file": "kasauti.ingest.worker:audit_file",  # one device of an upload (M2.04)
        "sort_files": "kasauti.ingest.sort:sort_files",  # recognise uploaded files (M2.06)
    }
)
