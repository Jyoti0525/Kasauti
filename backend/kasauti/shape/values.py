"""Recognisers for the typed slots of the mapping language and for pattern keys (PLAN §6.2, §9)."""

from __future__ import annotations

import ipaddress
import re

_INT = re.compile(r"^\d+$")
_DIGIT = re.compile(r"\d")
_IP_FIRST = frozenset("0123456789abcdefABCDEF:")
"""How an IPv4 or IPv6 address or prefix can start."""
_IFNAME = re.compile(r"^[A-Za-z][A-Za-z\-]*(\d+([/.:]\d+)*|\.\d+)$")
# Interface prefixes seen across the seed and unseen vendors. Used for pattern keys, where a
# false positive (``ipv4``, ``sha256``) would split one command into two patterns.
_KNOWN_IF = re.compile(
    r"^(ethernet|gigabitethernet|tengigabitethernet|fastethernet|twentyfivegige"
    r"|twentyfivegigabitethernet|fortygigabitethernet|hundredgige|hundredgigabitethernet"
    r"|appgigabitethernet|port-channel|bundle-ether|vlan|vlanif|loopback|tunnel|management"
    r"|mgmt|serial|dialer|bdi|virtual-template|nve|null|ge-|xe-|et-|ae|irb|lo|fxp|em|eth"
    r"|port|wan|dmz|bond|bridge|ether|sfp|sfp-sfpplus|te|gi|fa|po|vl|meth|xgigabitethernet"
    r"|gigabitethernet-|10ge|25ge|40ge|100ge)"
    r"-?\d+([/.:]\d+)*$",
    re.IGNORECASE,
)


def is_int(token: str) -> bool:
    return bool(_INT.match(token))


def is_ip(token: str) -> bool:
    """An IPv4/IPv6 address or prefix (``10.0.0.1``, ``10.0.0.0/24``, ``2001:db8::/32``)."""
    # Most tokens are words; ``ipaddress`` rejects them by raising, which costs microseconds
    # each, over every token of every line. An address has a digit or a colon (``::``).
    if not token or (token[0] not in _IP_FIRST) or not (":" in token or _DIGIT.search(token)):
        return False
    try:
        if "/" in token:
            ipaddress.ip_network(token, strict=False)
        else:
            ipaddress.ip_address(token)
    except ValueError:
        return False
    return True


def is_ifname(token: str) -> bool:
    """Permissive: any word followed by an interface number (``GigabitEthernet0/1``, ``wan1``,
    ``ge-0/0/0.0``, ``irb.100``). Used for ``<IFNAME>`` slots, where the mapping author has
    already said an interface belongs at this position."""
    return bool(_IFNAME.match(token))


def looks_like_ifname(token: str) -> bool:
    """Strict: only well-known interface prefixes. Used for pattern keys."""
    return bool(_KNOWN_IF.match(token))
