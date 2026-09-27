"""Which uploaded files belong to which device (PLAN §5.1; TODO M2.06).

An upload is a pile of files: configurations and the command outputs that come with them
(``show version``, ``show inventory``…, TODO M2.05). Before it starts, each file is recognised
in a worker (:mod:`kasauti.ingest.sort`): configuration or command output, vendor, and the
hostname it names, if any. This module turns that into devices, with no I/O of its own:

* **every configuration is a device** of its own, audited once;
* **a command output joins the configuration of the host it names**, of the same vendor;
* **one that names no host** (``show inventory`` and ``show chassis hardware`` don't) joins the
  configuration whose file name matches its own, less the command words and dates
  (``edge-r1.cfg`` and ``edge-r1_show_inventory.txt``), or, for generic names
  (``running-config.txt``, ``show_version.txt``), the name of the folder they share. A file
  named after the host (``EDGE-R1-inventory.txt``) matches that host's configuration too;
* **a tie or no match is never guessed**: the output is left out, with the reason, until
  someone pairs it by hand. Pairing by hand, or leaving an output out, wins over all of this;
* a file recognised as neither is audited on its own, and its audit says why it can't be.

The audit itself checks again: an output that names another host, or comes from another
vendor, is refused with the reason (:func:`kasauti.audit.audit`). So a wrong pairing, by
hand or otherwise, can't put one device's serial number in another's report.

File names here are untrusted labels. They are only compared, never used as paths, and are
split by plain character tests, never a regular expression.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

MAX_COMPANIONS = 8
"""Command outputs one configuration can take: the seven kinds PLAN §5.1 lists, and a spare.
Bounds what one audit's worker reads."""

_NOISE = frozenset(
    {
        # commands and their words
        "show", "sh", "display", "dis", "get", "run", "running", "startup", "start",
        "config", "configuration", "cfg", "conf", "version", "ver", "inventory", "inv",
        "system", "sys", "status", "info", "chassis", "hardware", "hw", "esn",
        # kinds of file, and extensions
        "backup", "bak", "output", "out", "copy", "txt", "log", "xml", "json", "yaml", "yml",
        "zip",
    }
)  # fmt: skip
"""Words that name a command, a kind of file or an extension, not a device."""


class Kind(StrEnum):
    CONFIG = "config"
    COMPANION = "companion"
    """A command output (TODO M2.05)."""
    UNKNOWN = "unknown"
    """Neither, as far as the installed packs can tell."""


class How(StrEnum):
    """How a file came to its device."""

    OWN = "own"
    """A configuration: its own device."""
    HOSTNAME = "hostname"
    NAME = "name"
    """By file or folder name."""
    HAND = "hand"
    """Paired, or left out, by hand."""
    ALONE = "alone"
    """Not recognised: audited on its own."""


@dataclass(frozen=True, slots=True)
class Recognised:
    kind: Kind
    vendor: str | None = None
    command: str | None = None
    """For a command output, which one (``show_version``…)."""
    hostname: str | None = None


@dataclass(frozen=True, slots=True)
class Member:
    """A file as grouping sees it."""

    id: str
    name: str
    recognised: Recognised | None
    """None while it is still being recognised."""
    manual: bool = False
    paired_with: str | None = None
    """With ``manual``: the configuration it was paired with by hand, or None if left out."""


@dataclass(frozen=True, slots=True)
class Placement:
    device: str | None
    """The id of the configuration whose audit the file is part of (its own, for a
    configuration or a file audited alone); None if it is in none."""
    how: How | None
    """None while the file is still being recognised."""
    note: str | None = None
    """Why it is left out, or audited alone."""


def words(text: str) -> list[str]:
    """``text`` as lower-case ASCII letter-and-digit runs."""
    return "".join(c if c.isascii() and c.isalnum() else " " for c in text.casefold()).split()


def host_key(hostname: str) -> str:
    """A hostname, compared the way file names are: ``EDGE_R1`` and ``edge-r1`` are the same."""
    return "-".join(words(hostname))


def name_key(name: str) -> str | None:
    """What a file's name says about its device: the file name without command words, file
    types and dates, or the nearest folder's if nothing is left (``r1/show_version.txt``)."""
    for part in reversed(name.split("/")):
        kept = [w for w in _without_dates(words(part)) if w not in _NOISE]
        if kept:
            return "-".join(kept)
    return None


def _without_dates(tokens: list[str]) -> list[str]:
    """``tokens`` without dates and the times after them (``2026-09-27``, ``20260927``,
    ``2026_09_27_1030``), which differ between a device's files taken minutes apart."""
    out: list[str] = []
    i = 0
    while i < len(tokens):
        if _stamp(tokens[i]):
            i += 1
        elif _year(tokens[i]) and i + 2 < len(tokens) and _part(tokens[i + 1], 12):
            if not _part(tokens[i + 2], 31):
                out.append(tokens[i])
                i += 1
                continue
            i += 3
        else:
            out.append(tokens[i])
            i += 1
            continue
        while i < len(tokens) and tokens[i].isdigit() and len(tokens[i]) in (2, 4, 6):
            i += 1  # a time after the date
    return out


def _year(token: str) -> bool:
    return len(token) == 4 and token.isdigit() and token[:2] in ("19", "20")


def _part(token: str, most: int) -> bool:
    return len(token) <= 2 and token.isdigit() and 1 <= int(token) <= most


def _stamp(token: str) -> bool:
    """``20260927``, ``202609271030``, ``20260927103015``."""
    return token.isdigit() and len(token) in (8, 12, 14) and _year(token[:4])


def group(members: Sequence[Member]) -> dict[str, Placement]:
    """Where each file goes, by id (see the module's description)."""
    out: dict[str, Placement] = {}
    configs: list[Member] = []
    companions: list[Member] = []
    for m in members:
        r = m.recognised
        if r is None:
            out[m.id] = Placement(None, None)
        elif r.kind is Kind.CONFIG:
            out[m.id] = Placement(m.id, How.OWN)
            configs.append(m)
        elif r.kind is Kind.COMPANION:
            companions.append(m)
        else:
            out[m.id] = Placement(
                m.id,
                How.ALONE,
                "not recognised as a configuration or a command output: it is audited on its "
                "own, and its audit says why if it can't be",
            )
    by_id = {c.id: c for c in configs}
    taken: Counter[str] = Counter()
    companions.sort(key=lambda m: (m.name, m.id))
    for m in companions:
        if m.manual:
            if m.paired_with in by_id:
                out[m.id] = Placement(m.paired_with, How.HAND)
                taken[m.paired_with] += 1
            else:
                out[m.id] = Placement(None, How.HAND, "left out by hand: used in no audit")
    for m in companions:
        if not m.manual and m.recognised is not None:
            out[m.id] = _place(m, m.recognised, configs, taken)
    return out


def _place(m: Member, r: Recognised, configs: Sequence[Member], taken: Counter[str]) -> Placement:
    same_vendor = [c for c in configs if c.recognised and c.recognised.vendor == r.vendor]
    own = name_key(m.name)
    if r.hostname:
        host = host_key(r.hostname)
        found = [c for c in same_vendor if _host(c) == host]
        how = How.HOSTNAME
        if len(found) > 1 and own is not None:
            # Two configurations of one host (running and startup, two dates): the file name
            # decides, when it can.
            by_name = [c for c in found if name_key(c.name) == own]
            found = by_name if len(by_name) == 1 else found
        if not found:
            # A configuration with no hostname line may still be this host's.
            found = [c for c in same_vendor if _host(c) is None and name_key(c.name) == own]
            how = How.NAME
        if not found:
            return Placement(
                None,
                How.HOSTNAME,
                f"names host {r.hostname}, and no configuration here is that host",
            )
    else:
        found = (
            [c for c in same_vendor if own in (name_key(c.name), _host(c))]
            if own is not None
            else []
        )
        how = How.NAME
        if not found:
            return Placement(
                None,
                How.NAME,
                "names no host, and no configuration here matches its file or folder name: "
                "pair it by hand",
            )
    if len(found) > 1:
        names = ", ".join(sorted(c.name for c in found)[:3])
        more = "…" if len(found) > 3 else ""
        return Placement(
            None, how, f"matches {len(found)} configurations ({names}{more}): pair it by hand"
        )
    (config,) = found
    if taken[config.id] >= MAX_COMPANIONS:
        return Placement(None, how, f"{config.name} already has {MAX_COMPANIONS} command outputs")
    taken[config.id] += 1
    return Placement(config.id, how)


def _host(m: Member) -> str | None:
    r = m.recognised
    return host_key(r.hostname) if r is not None and r.hostname else None


__all__ = [
    "MAX_COMPANIONS",
    "How",
    "Kind",
    "Member",
    "Placement",
    "Recognised",
    "group",
    "host_key",
    "name_key",
    "words",
]
