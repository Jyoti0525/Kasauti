"""Device details entered by hand: identity source 4 (PLAN §7; TODO M2.19).

A serial number is rarely in a configuration, and not every site can send ``show inventory``.
The operator can then type it, and the model, hardware, OS version or hostname, for a device
before its audit starts. What they type is the last source, after live facts, command outputs
and the configuration: it fills only a field none of those did, and where the files say
something else, the files win and the audit says so.

It is shown in the report's device profile, marked as entered by hand, and nowhere else. It is
never a fact in the Security Baseline Model, which holds only what the files show, with the
lines that show it, and it never changes a verdict: an OS version typed by hand doesn't choose
version-scoped mappings or vendor defaults, since a typo there could turn a REVIEW into a false
PASS (:mod:`kasauti.mapping.defaults`).

Values come from the user, so they are checked like input: known fields only, printable text
on one line, a length limit.
"""

from __future__ import annotations

from collections.abc import Mapping

ENTERABLE = ("hostname", "os_version", "model", "serial", "hardware")
"""Every identity field but the vendor, which is the vendor pack the audit uses: chosen with
the upload (or ``--vendor``), not typed here."""
VALUE_LIMIT = 128
"""Characters per value: longer than any hostname (63 per label), serial or model name."""
SOURCE = "entered by hand; not in the supplied files"
"""The source the report gives a field filled this way."""


class ManualEntryError(ValueError):
    """Values that can't be taken. The message is user-safe: it names fields, never values."""


def clean_entered(values: Mapping[str, object]) -> dict[str, str]:
    """``values`` checked and trimmed, in :data:`ENTERABLE` order; an empty value is dropped
    (clearing that field). :class:`ManualEntryError` if any is not acceptable."""
    if not isinstance(values, Mapping):
        raise ManualEntryError("device details are given as field: value pairs")
    unknown = sorted(str(k) for k in values if k not in ENTERABLE)
    if unknown:
        raise ManualEntryError(
            f"no such device detail: {', '.join(unknown)} (these can be entered: "
            f"{', '.join(ENTERABLE)})"
        )
    out: dict[str, str] = {}
    for field in ENTERABLE:
        value = values.get(field)
        if value is None:
            continue
        if not isinstance(value, str):
            raise ManualEntryError(f"{field}: must be text")
        text = value.strip()
        if len(text) > VALUE_LIMIT:
            raise ManualEntryError(f"{field}: at most {VALUE_LIMIT} characters")
        # Not printable: control and format characters (a line break, a right-to-left
        # override that would make a report show one serial and hold another), unassigned ones.
        if not text.isprintable():
            raise ManualEntryError(f"{field}: printable characters on one line only")
        if text:
            out[field] = text
    return out


__all__ = ["ENTERABLE", "SOURCE", "VALUE_LIMIT", "ManualEntryError", "clean_entered"]
