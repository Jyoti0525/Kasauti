"""What ingestion hands to the pipeline core (PLAN §5)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Artifact:
    """One ingested file after validation, decoding and hashing."""

    name: str
    """Display name used in evidence (the file name, never a local absolute path)."""
    text: str
    sha256: str
    """Of the original bytes, so the report's hash matches the file the user holds."""
    encoding: str
    kind: str = "config"
    """``config`` or a companion kind such as ``show_version`` (§5.1)."""
