"""The worker pool: runs queued jobs in separate processes (PLAN §4.2; TODO M2.03).

One process per job, started fresh (``spawn``, on every OS). A configuration that crashes or
hangs the parser takes down only its own process: the pool records the job as failed and goes
on. Nothing one job leaves behind in memory can reach the next. Starting a process costs about
0.1 s, small beside an audit. Each worker caps its own memory first (:mod:`kasauti.jobs.limits`),
so a file too large to audit fails its job instead of exhausting the machine; the wall-clock
limit is enforced here. Confining workers further (CPU, files) is M5.02.

The worker processes never see the database (their side, :mod:`kasauti.jobs.child`, doesn't
even import it). They get the handler and payload when they start,
and send back one message, which the pool reads with a size limit: a result as gzip-compressed
canonical JSON (:mod:`kasauti.jobs.results`), checked but not parsed, so it costs the server no
more than its compressed size; or a small JSON object saying why the job failed. Never a
pickle: a process that a hostile file has taken over could otherwise run code in the server by
what it sends back.

Errors shown for a failed job are the handler's own :class:`JobError` messages, which are written
to be shown; for anything else only the exception's type is recorded, since an exception's text
may quote the configuration being parsed.

The pool is driven by :meth:`WorkerPool.tick`, from a background thread (:meth:`start`) in
``kasauti serve``, or directly (:meth:`run_until_idle`).
"""

from __future__ import annotations

import datetime as dt
import json
import multiprocessing
import os
import socket
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from multiprocessing.connection import wait
from multiprocessing.process import BaseProcess
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from kasauti.jobs import child
from kasauti.jobs.child import (
    JobError,
    resolve,
    set_worker_secrets,
    worker_secret,
)
from kasauti.jobs.limits import DEFAULT_MEMORY_MIB, MIN_MEMORY_MIB
from kasauti.jobs.queue import Claim, JobQueue
from kasauti.jobs.results import (
    GZIP_MAGIC,
    RESULT_EXPANDED_LIMIT,
    RESULT_LIMIT,
    ResultError,
    ResultTooLargeError,
    check_result,
)
from kasauti.jobs.table import JobState
from kasauti.log import get_logger

__all__ = ["JobError", "WorkerPool", "default_workers", "set_worker_secrets", "worker_secret"]

log = get_logger(__name__)

_CONTEXT = multiprocessing.get_context("spawn")
_MESSAGE_LIMIT = 64 * 1024
"""Bytes of a message that isn't a result (why the job failed)."""


def default_workers() -> int:
    """Two, or one on a machine with fewer than four CPUs: parsing is CPU-bound, and the
    laptop this runs on also hosts the optional local LLM (PLAN Appendix B)."""
    return 2 if (os.cpu_count() or 1) >= 4 else 1


def _has_message(conn: Any) -> bool:
    """Something to read: the message, or (POSIX) the end of a pipe whose writer exited."""
    try:
        return bool(conn.poll())
    except OSError:  # Windows: the writer exited and nothing is left unread
        return False


@dataclass(slots=True)
class _Running:
    claim: Claim
    process: BaseProcess
    conn: Any
    """The receiving end: a Connection, or on Windows a PipeConnection."""
    deadline: float
    started: float = field(default_factory=time.monotonic)


class WorkerPool:
    """Runs this queue's jobs, ``workers`` at a time."""

    def __init__(
        self,
        queue: JobQueue,
        handlers: Mapping[str, str],
        *,
        workers: int | None = None,
        poll_s: float = 0.5,
        heartbeat_s: float = 10.0,
        lease: dt.timedelta = dt.timedelta(seconds=60),
        grace_s: float = 10.0,
        memory_mib: int = DEFAULT_MEMORY_MIB,
        secrets: Mapping[str, bytes] | None = None,
    ) -> None:
        if set(handlers) != set(queue.kinds):
            raise ValueError("the pool's handlers and the queue's kinds differ")
        for target in handlers.values():
            resolve(target)  # a typo stops the server now, not every job later
        self.queue = queue
        self.handlers = dict(handlers)
        self.workers = default_workers() if workers is None else workers
        if self.workers < 1:
            raise ValueError("a pool needs at least one worker")
        if memory_mib < MIN_MEMORY_MIB:
            raise ValueError(f"a worker needs at least {MIN_MEMORY_MIB} MiB")
        self.memory_mib = memory_mib
        self._secrets = dict(secrets or {})
        self.poll_s = poll_s
        self.heartbeat_s = heartbeat_s
        self.lease = lease
        self.grace_s = grace_s
        # Unique per pool, so two pools in one process (or a restarted one) never share jobs.
        self.name = f"{socket.gethostname()[:64]}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self._running: dict[str, _Running] = {}
        self._last_heartbeat = 0.0
        self._last_recover = 0.0
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- driving ------------------------------------------------------------------------------

    def start(self) -> None:
        """Run the pool in a background thread until :meth:`stop`."""
        if self._thread is not None:
            raise RuntimeError("the pool is already running")
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="kasauti-jobs", daemon=True)
        self._thread.start()
        log.info("job pool started", pool=self.name, workers=self.workers)

    def stop(self) -> None:
        """Stop claiming, give running jobs ``grace_s`` to finish, then stop them and put them
        back in the queue (the attempt isn't counted)."""
        if self._thread is None:
            return
        self._stop.set()
        self._wake.set()
        self._thread.join()
        self._thread = None
        self._drain()
        log.info("job pool stopped", pool=self.name)

    def wake(self) -> None:
        """A job was queued: look now rather than at the next poll."""
        self._wake.set()

    def run_until_idle(self, timeout_s: float = 60.0) -> None:
        """Run jobs until none are running or queued; :class:`TimeoutError` after
        ``timeout_s``. For the command line and tests; the server uses :meth:`start`."""
        deadline = time.monotonic() + timeout_s
        while True:
            self.tick()
            if not self._running and not self.queue.pending():
                return
            if time.monotonic() > deadline:
                self._drain(grace_s=0)
                raise TimeoutError(f"jobs still running after {timeout_s} s")
            self._wait()

    @property
    def running(self) -> tuple[str, ...]:
        return tuple(self._running)

    def tick(self) -> None:
        """One round: collect finished jobs, enforce limits, renew leases, recover lost jobs,
        and start queued ones in the free slots."""
        self._collect()
        now = time.monotonic()
        if self._running and now - self._last_heartbeat >= self.heartbeat_s:
            self._heartbeat()
            self._last_heartbeat = now
        if now - self._last_recover >= self.lease.total_seconds() / 2:
            recovered = self.queue.recover(self.lease)
            if recovered:
                log.warning("jobs recovered from a lost worker", jobs=recovered)
            self._last_recover = now
        free = self.workers - len(self._running)
        if free > 0 and not self._stop.is_set():
            for claim in self.queue.claim(self.name, free):
                self._spawn(claim)

    # -- internals ----------------------------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except SQLAlchemyError as err:
                # The database is briefly unavailable (locked, restarting): try again later.
                log.warning("job pool can't reach the database", error=type(err).__name__)
                self._stop.wait(self.poll_s * 4)
            except Exception:
                log.exception("job pool round failed")
                self._stop.wait(self.poll_s * 4)
            self._wait()

    def _wait(self) -> None:
        """Until a job finishes, a job is queued here, or ``poll_s`` passes."""
        if self._running:
            handles: list[Any] = []
            for run in self._running.values():
                handles += [run.conn, run.process.sentinel]
            wait(handles, timeout=self.poll_s)
        else:
            self._wake.wait(self.poll_s)
        self._wake.clear()

    def _spawn(self, claim: Claim) -> None:
        receive, send = _CONTEXT.Pipe(duplex=False)
        process = _CONTEXT.Process(
            target=child.run,
            args=(send, self.handlers[claim.kind], claim.payload, self.memory_mib, self._secrets),
            name=f"kasauti-job-{claim.id[:8]}",
            daemon=True,
        )
        try:
            process.start()
        except OSError as err:
            receive.close()
            self._finish(claim, JobState.FAILED, error=f"couldn't start a worker ({err.strerror})")
            return
        finally:
            send.close()  # the child holds its own copy; ours would hide the child's exit
        self._running[claim.id] = _Running(
            claim, process, receive, deadline=time.monotonic() + claim.timeout_s
        )
        log.info("job started", job=claim.id, kind=claim.kind, pid=process.pid)

    def _collect(self) -> None:
        for job_id, run in list(self._running.items()):
            if _has_message(run.conn):
                self._read(run)
            elif not run.process.is_alive():
                # It may have written just before exiting.
                if _has_message(run.conn):
                    self._read(run)
                else:
                    self._crashed(run)
            elif time.monotonic() > run.deadline:
                self._end(run, JobState.FAILED, error=f"timed out after {run.claim.timeout_s} s")
            else:
                continue
            self._running.pop(job_id, None)

    def _read(self, run: _Running) -> None:
        try:
            raw = run.conn.recv_bytes(RESULT_LIMIT)
        except EOFError:
            self._crashed(run)
            return
        except OSError:
            error = f"the result is over {RESULT_LIMIT} bytes compressed"
            self._end(run, JobState.FAILED, error=error)
            return
        if raw.startswith(GZIP_MAGIC):
            try:
                check_result(raw, limit=RESULT_EXPANDED_LIMIT)
            except ResultTooLargeError:
                error = f"the result is over {RESULT_EXPANDED_LIMIT} bytes uncompressed"
                self._end(run, JobState.FAILED, error=error)
            except ResultError as err:
                log.warning("unreadable job result", job=run.claim.id, why=str(err))
                self._end(run, JobState.FAILED, error="the worker sent an unreadable result")
            else:
                self._end(run, JobState.SUCCEEDED, result=raw)
            return
        message: object = {}
        if len(raw) <= _MESSAGE_LIMIT:
            try:
                message = json.loads(raw)
            except (ValueError, RecursionError):  # also nesting deep enough to exhaust the stack
                message = {}
        if not isinstance(message, dict):
            message = {}
        if isinstance(message.get("error"), str):
            self._end(run, JobState.FAILED, error=message["error"])
        elif isinstance(message.get("exception"), str):
            name = message["exception"][:80]
            self._end(run, JobState.FAILED, error=f"the job failed with an internal error ({name})")
        else:
            self._end(run, JobState.FAILED, error="the worker sent an unreadable result")

    def _crashed(self, run: _Running) -> None:
        run.process.join(timeout=5)
        code = run.process.exitcode
        self._end(
            run, JobState.FAILED, error=f"the worker process ended unexpectedly (exit {code})"
        )

    def _heartbeat(self) -> None:
        lost, cancelled = self.queue.heartbeat(self.name, list(self._running))
        for job_id in lost:
            run = self._running.pop(job_id)
            self._stop_process(run)
            log.warning("job taken over by another worker; stopped here", job=job_id)
        for job_id in cancelled:
            run = self._running.pop(job_id)
            self._end(run, JobState.CANCELLED, error="cancelled while running")

    def _end(
        self,
        run: _Running,
        state: JobState,
        *,
        result: bytes | None = None,
        error: str | None = None,
    ) -> None:
        self._stop_process(run)
        self._finish(run.claim, state, result=result, error=error, seconds=run.started)

    def _finish(
        self,
        claim: Claim,
        state: JobState,
        *,
        result: bytes | None = None,
        error: str | None = None,
        seconds: float | None = None,
    ) -> None:
        recorded = self.queue.finish(self.name, claim.id, state, result=result, error=error)
        took = None if seconds is None else round(time.monotonic() - seconds, 3)
        if recorded:
            log.info("job finished", job=claim.id, kind=claim.kind, state=state.value, seconds=took)
        else:
            log.warning("job finished after this pool lost it; result dropped", job=claim.id)

    @staticmethod
    def _stop_process(run: _Running) -> None:
        if run.process.is_alive():
            run.process.kill()
        run.process.join(timeout=5)
        run.conn.close()
        if run.process.exitcode is not None:  # close() refuses a process still exiting
            run.process.close()

    def _drain(self, grace_s: float | None = None) -> None:
        """Let running jobs finish within the grace period; release the rest to the queue."""
        deadline = time.monotonic() + (self.grace_s if grace_s is None else grace_s)
        while self._running and time.monotonic() < deadline:
            self._collect()
            if self._running:
                self._wait()
        if not self._running:
            return
        for run in self._running.values():
            self._stop_process(run)
        released = self.queue.release(self.name, list(self._running))
        log.info("jobs returned to the queue at shutdown", jobs=list(self._running), n=released)
        self._running.clear()
