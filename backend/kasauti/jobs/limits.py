"""A memory ceiling for a worker process (TODO M2.04 follow-up; the memory part of M5.02).

An audit's memory grows with the configuration: about 200 MiB per MiB of a typical dense
configuration, and 470 MiB per MiB of the densest input found (measured 2026-09-27). Without
a ceiling, one large or hostile file could push the whole laptop into swap. With one, the
allocation that would cross it fails, Python raises :class:`MemoryError`, and only that job
fails, with a message saying why.

The worker applies the ceiling to itself before it runs anything else: on Windows a job
object with a per-process memory limit (committed memory), elsewhere ``RLIMIT_AS`` (address
space, a little stricter). This guards against a file's size, not against a worker taken over
by a hostile file, which could lift its own limit; confining such a worker is the rest of
M5.02 (sandboxing).
"""

from __future__ import annotations

import sys

MIB = 1024 * 1024
DEFAULT_MEMORY_MIB = 2048
"""Enough for about 10 MiB of a typical dense configuration; two workers stay inside a 16 GB
laptop with room for the rest. ``kasauti serve --worker-memory`` changes it."""
MIN_MEMORY_MIB = 256
"""Below this a worker can't load the knowledge base."""


def limit_memory(mib: int) -> None:
    """Cap this process's memory at ``mib`` MiB. :class:`OSError` if the system refuses."""
    if mib < MIN_MEMORY_MIB:
        raise ValueError(f"a worker needs at least {MIN_MEMORY_MIB} MiB")
    if sys.platform == "win32":
        _limit_windows(mib * MIB)
    else:
        import resource  # noqa: PLC0415 (POSIX only)

        resource.setrlimit(resource.RLIMIT_AS, (mib * MIB, mib * MIB))


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100

    class _BasicLimits(ctypes.Structure):
        _fields_ = (
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        )

    class _IoCounters(ctypes.Structure):
        _fields_ = tuple((name, ctypes.c_uint64) for name in ("r", "w", "o", "rb", "wb", "ob"))

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = (
            ("BasicLimitInformation", _BasicLimits),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        )

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE

    _held: list[int] = []
    """The job handle, kept open for the life of the process."""

    def _limit_windows(limit: int) -> None:
        job = _kernel32.CreateJobObjectW(None, None)
        if not job:
            raise ctypes.WinError(ctypes.get_last_error())
        info = _ExtendedLimits()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_PROCESS_MEMORY
        info.ProcessMemoryLimit = limit
        if not _kernel32.SetInformationJobObject(
            job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        # Jobs nest (Windows 8+), so this works inside a terminal's or an IDE's own job.
        if not _kernel32.AssignProcessToJobObject(job, _kernel32.GetCurrentProcess()):
            raise ctypes.WinError(ctypes.get_last_error())
        _held.append(job)


__all__ = ["DEFAULT_MEMORY_MIB", "MIN_MEMORY_MIB", "limit_memory"]
