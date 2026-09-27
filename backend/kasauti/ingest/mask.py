"""Kind-preserving secret masking (PLAN §5.2, TODO M2.08, first cut in M1).

Evidence lines end up in reports, JSON exports and the Training Studio, so secret *values* are
replaced with ``****``. The *kind* of secret is kept (``password 7 ****``, ``secret 9 ****``,
``community **** RO``), so rules like "no reversible password types" still work and the auditor
still sees what was configured.

Masking is applied to display text only. Mappings match the original statement in memory
(e.g. to recognise the well-known community ``public``), and nothing unmasked is persisted.

The rules are deliberately vendor-generic and err on the side of masking. A missed secret is
a leak; an over-masked word only costs a little readability. They were reviewed vendor by
vendor against each one's command reference (M2.08, ``tests/ingest/test_mask_vendors.py``):
most secrets follow a keyword, a few don't (a Cisco trap host's community, an HSRP text key,
a FortiGate's community, which is its ``set name``). What isn't a secret stays readable: a key's
number, a password policy, a key chain's name.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

MASK = "****"

_TOKEN = re.compile(r'"[^"]*"|\S+')

# A secret value follows these words (after any type/algorithm words, see _SKIP).
_KEYWORDS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "key",
        "key-string",
        "community",
        "pre-shared-key",
        "psksecret",
        "psk",
        "wpa-psk",
        "authentication-key",
        "message-digest-key",
        "privacy-key",
        "encrypted-password",
        "local-password",
        "chap-secret",
        "passphrase",
        "auth-password",
        "priv-password",
        "auth-pwd",
        "priv-pwd",
        "private-key",
        "shared-secret",
        "secret-key",
        "md5-key",
        "auth-key",
        "ppk-secret",
        "secondary-secret",
        "tertiary-secret",
        "secondary-key",
        "tertiary-key",
        "password-encryption",  # Cisco ``key config-key password-encryption KEY``: the master key
        # PAN-OS XML element names (rendered as "<element> <value>").
        "phash",
        "snmp-community-string",
        "bind-password",
        "authpwd",
        "privpwd",
    }
)
# Words between the keyword and the value that describe the secret's kind, or which one it is
# (a key's number, IKEv2's ``local``/``remote`` key, Cisco's privilege ``level``). Kept visible.
_SKIP = re.compile(
    r"^(\d{1,3}[a-z]?|enc|encrypted|unencrypted|ascii-text|ascii|hexadecimal|hex|cipher|hash"
    r"|plaintext|md5|sha\S*|hmac-\S+|aes\S*|des|3des|0x|level|local|remote|type|value)$",
    re.IGNORECASE,
)
# Words that follow a keyword in commands that hold no secret (``crypto key generate``,
# ``key chain NAME``, BGP ``set community 65000:100``, Arista ``password minimum length``, Cisco
# ``password encryption aes``, Junos ``authentication-order [ tacplus password ]``).
_NOT_SECRET = re.compile(
    r"^(generate|chain|zeroize|config-key|storage|rsa|ec|label|modulus|exchange|export|import"
    r"|pubkey-chain|\d+:\d+|internet|no-export|no-advertise|local-as|additive|none|minimum"
    r"|encryption|[\[\]{};]+)$",
    re.IGNORECASE,
)
# SNMPv3 ``auth sha SECRET`` / ``priv aes 128 SECRET``: only masked when an algorithm follows.
_ALGO = re.compile(r"^(md5|sha\S*|aes\S*|des|3des)$", re.IGNORECASE)


def mask_secrets(text: str, path: Sequence[str] = ()) -> str:
    """``text`` with every secret value replaced by :data:`MASK`. ``path`` is the statement's
    enclosing blocks, where the parser gave them: a few secrets are known only by where they
    are (a FortiGate's SNMP community is its ``set name``)."""
    spans = [(m.start(), m.end(), m.group()) for m in _TOKEN.finditer(text)]
    words = [s[2] for s in spans]
    secret = _secret_indexes(words, [" ".join(p.lower().split()) for p in path])
    if not secret and "=" not in text:
        return text
    out: list[str] = []
    pos = 0
    for i, (start, end, word) in enumerate(spans):
        out.append(text[pos:start])
        if i in secret:
            out.append(f'"{MASK}"' if word.startswith('"') else MASK)
        else:
            out.append(_mask_assignment(word))
        pos = end
    out.append(text[pos:])
    return "".join(out)


def _secret_indexes(words: list[str], path: list[str]) -> set[int]:
    lower = [w.lower() for w in words]
    ntp = "ntp" in lower or any("ntp" in p.split() for p in path)
    found: set[int] = set()
    for i, word in enumerate(lower):
        if word in _KEYWORDS:
            if word == "key" and ntp and i + 1 < len(words) and words[i + 1].isdigit():
                continue  # ``ntp server ADDR key 1``: the key's number
            j = i + 1
            while j < len(words) and _SKIP.match(words[j]) and j < len(words) - 1:
                j += 1
            if j < len(words) and not _NOT_SECRET.match(words[j]):
                found.add(j)
        elif word in ("auth", "priv") and i + 2 < len(words) and _ALGO.match(words[i + 1]):
            j = i + 2
            if words[j].isdigit() and j + 1 < len(words):  # key size, e.g. ``aes 128``
                j += 1
            found.add(j)
    found |= _snmp_host_community(lower)
    found |= _redundancy_text_key(lower)
    if "config system snmp community" in path and lower[:2] == ["set", "name"] and len(lower) > 2:
        found.add(2)  # FortiOS: the community string is the entry's name
    return found


def _snmp_host_community(lower: list[str]) -> set[int]:
    """``snmp-server host ADDR [vrf NAME | informs | traps | version {1 | 2c | 3 LEVEL}]
    COMMUNITY``: the community has no keyword. With SNMPv3 the word there is a user name."""
    if lower[:2] != ["snmp-server", "host"] or len(lower) < 4:
        return set()
    j = 3
    while j < len(lower):
        if lower[j] == "vrf":
            j += 2
        elif lower[j] in ("informs", "traps"):
            j += 1
        elif lower[j] == "version":
            if j + 1 < len(lower) and lower[j + 1] == "3":
                return set()
            j += 2
        else:
            break
    return {j} if j < len(lower) else set()


def _redundancy_text_key(lower: list[str]) -> set[int]:
    """HSRP ``standby [N] authentication [text] KEY`` and VRRP ``vrrp N [peer] authentication
    text KEY``: a plain-text key with no keyword. ``md5 key-string KEY`` is masked by its
    keyword; a ``key-chain`` name isn't a secret."""
    if not lower or lower[0] not in ("standby", "vrrp") or "authentication" not in lower:
        return set()
    j = lower.index("authentication") + 1
    if j < len(lower) and lower[j] == "text":
        j += 1
    if j >= len(lower) or "md5" in lower[j]:
        return set()
    return {j}


def _mask_assignment(word: str) -> str:
    """``password=abc`` (MikroTik and similar) keeps the key and hides the value."""
    key, sep, value = word.partition("=")
    if sep and value and key.lower() in _KEYWORDS:
        return f"{key}={MASK}"
    return word
