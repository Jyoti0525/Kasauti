"""Background jobs: a queue in the database and a pool of worker processes, no broker
(PLAN §4.2, §19.1; TODO M2.03). See :mod:`kasauti.jobs.queue` and :mod:`kasauti.jobs.pool`.

The names below are imported when first used, not with the package: a worker process imports
:mod:`kasauti.jobs.child`, and with it this package, and must not pay for the database layer
the queue and the pool are built on (M2.09).
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from kasauti.jobs.child import JobError
    from kasauti.jobs.pool import WorkerPool, default_workers
    from kasauti.jobs.queue import Job, JobInputError, JobQueue
    from kasauti.jobs.table import JobState

_WHERE = {
    "Job": "kasauti.jobs.queue",
    "JobError": "kasauti.jobs.child",
    "JobInputError": "kasauti.jobs.queue",
    "JobQueue": "kasauti.jobs.queue",
    "JobState": "kasauti.jobs.table",
    "WorkerPool": "kasauti.jobs.pool",
    "default_workers": "kasauti.jobs.pool",
}

__all__ = [
    "Job",
    "JobError",
    "JobInputError",
    "JobQueue",
    "JobState",
    "WorkerPool",
    "default_workers",
]


def __getattr__(name: str) -> Any:
    module = _WHERE.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(module), name)
