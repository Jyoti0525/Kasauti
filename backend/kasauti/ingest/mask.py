"""Kind-preserving secret masking (PLAN §5.2, TODO M2.08, first cut in M1).

Evidence lines end up in reports, JSON exports and the Training Studio, so secret *values* are
replaced with ``****``. The *kind* of secret is kept (``password 7 ****``, ``secret 9 ****``,
``community **** RO``), so rules like "no reversible password types" still work and the auditor
still sees what was configured.

Masking is applied to display text only. Mappings match the original statement in memory
(e.g. to recognise the well-known community ``public``), and nothing unmasked is persisted.

The rules are deliberately vendor-generic and err on the side of masking. A missed secret is
a leak; an over-masked word only costs a little readability.
"""

from __future__ import annotations

import re

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
        "authentication-key",
        "message-digest-key",
        "encrypted-password",
        "passphrase",
        "auth-password",
        "priv-password",
        "private-key",
        "shared-secret",
        "secret-key",
        "md5-key",
        "auth-key",
    }
)
# Words between the keyword and the value that describe the secret's kind. Kept visible.
_SKIP = re.compile(
    r"^(\d{1,3}|enc|encrypted|unencrypted|ascii-text|hexadecimal|hex|cipher|hash|plaintext"
    r"|md5|sha\S*|hmac-\S+|aes\S*|des|3des|0x)$",
    re.IGNORECASE,
)
# Words that follow ``key``/``community`` in non-secret commands (``crypto key generate``,
# ``key chain NAME``, BGP ``set community 65000:100``).
_NOT_SECRET = re.compile(
    r"^(generate|chain|zeroize|config-key|storage|rsa|ec|label|modulus|exchange|export|import"
    r"|pubkey-chain|\d+:\d+|internet|no-export|no-advertise|local-as|additive|none)$",
    re.IGNORECASE,
)
# SNMPv3 ``auth sha SECRET`` / ``priv aes 128 SECRET``: only masked when an algorithm follows.
_ALGO = re.compile(r"^(md5|sha\S*|aes\S*|des|3des)$", re.IGNORECASE)
_SNMP_HOST_OPTIONS = frozenset({"version", "informs", "traps", "vrf", "1", "2c", "3"})


def mask_secrets(text: str) -> str:
    spans = [(m.start(), m.end(), m.group()) for m in _TOKEN.finditer(text)]
    words = [s[2] for s in spans]
    secret = _secret_indexes(words)
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


def _secret_indexes(words: list[str]) -> set[int]:
    lower = [w.lower() for w in words]
    found: set[int] = set()
    for i, word in enumerate(lower):
        if word in _KEYWORDS:
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
    return found


def _snmp_host_community(lower: list[str]) -> set[int]:
    """``snmp-server host 192.0.2.1 [version 1|2c] COMMUNITY``: the community has no keyword."""
    if lower[:2] != ["snmp-server", "host"] or len(lower) < 4:
        return set()
    if "3" in lower[3:6] and "version" in lower[3:5]:
        return set()  # SNMPv3: the next word is a user name, not a secret
    j = 3
    while j < len(lower) and lower[j] in _SNMP_HOST_OPTIONS:
        j += 1
    return {j} if j < len(lower) else set()


def _mask_assignment(word: str) -> str:
    """``password=abc`` (MikroTik and similar) keeps the key and hides the value."""
    key, sep, value = word.partition("=")
    if sep and value and key.lower() in _KEYWORDS:
        return f"{key}={MASK}"
    return word
