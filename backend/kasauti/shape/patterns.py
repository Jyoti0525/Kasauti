"""Pattern keys (PLAN §6.2, TODO M1.03): group statements that differ only in their values.

48 interface blocks collapse into one ``interface <IFNAME>`` pattern, so the admin teaches a
pattern once in the Training Studio, not 48 times.

Why not Drain3, as the plan first said (changelog v5.1.3): Drain3 has had no release since 2022,
pulls jsonpickle into the runtime, and its similarity merge is wrong for configurations: with
default settings ``ip ssh version 2`` and ``ip ssh time-out 60`` share 3 of 4 tokens and merge into
``ip ssh <*> <NUM>``, one pattern for two different security settings. Configurations are
keyword-driven, so keywords stay literal and only *values* are abstracted, by type. The key of
a statement depends on that statement alone, so it is deterministic and order-independent.
"""

from __future__ import annotations

from kasauti.shape.values import is_int, is_ip, looks_like_ifname

_SECRETISH_MIN = 16


def token_class(token: str) -> str | None:
    """The slot type a value token abstracts to, or None for a keyword."""
    if token.startswith('"'):
        return "<STR>"
    if is_int(token):
        return "<INT>"
    if is_ip(token):
        return "<IP>"
    if looks_like_ifname(token):
        return "<IFNAME>"
    if _secretish(token):
        return "<STR>"
    return None


def pattern_key(tokens: tuple[str, ...]) -> str:
    return " ".join(token_class(t) or t for t in tokens)


def _secretish(token: str) -> bool:
    """Hashes, keys, serials: long tokens mixing letters and digits, or crypt-style ``$…$``."""
    if token.startswith("$") and token.count("$") >= 2:
        return True
    return (
        len(token) >= _SECRETISH_MIN
        and any(c.isdigit() for c in token)
        and any(c.isalpha() for c in token)
        and "-" not in token
    )
