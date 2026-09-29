"""Accounts, passwords and sign-in sessions (PLAN §17; TODO M5.03-M5.05).

* **Passwords** are hashed with Argon2id (argon2-cffi, RFC 9106's low-memory profile) and must
  be at least :data:`MIN_PASSWORD` characters, as NIST SP 800-63B-4 requires of a password used
  on its own; no composition rules, which that standard also forbids.
* **Wrong passwords**: after :data:`MAX_FAILURES` in a row the account is refused for
  :data:`LOCKOUT` (also on the right password), which caps guessing at a few hundred tries a day.
  An unknown name costs a hash too, so timing doesn't tell which names exist.
* **Sessions** are rows keyed by the SHA-256 of a random token; the browser holds the token in
  an HttpOnly, SameSite=Strict cookie. A session ends after :data:`IDLE` without a request, or
  :data:`LIFETIME` after sign-in, whichever comes first, and on sign-out.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import secrets
import uuid
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import Engine, delete, func, insert, select, update
from sqlalchemy.exc import IntegrityError

from kasauti.accounts.table import NAME_LIMIT, RANK, Role, accounts, sessions
from kasauti.jobs.queue import utcnow

MIN_PASSWORD = 15
MAX_PASSWORD = 128
MAX_FAILURES = 5
LOCKOUT = dt.timedelta(minutes=5)
IDLE = dt.timedelta(minutes=30)
LIFETIME = dt.timedelta(hours=12)
SEEN_EVERY = dt.timedelta(minutes=1)
"""How stale ``seen_at`` may get before a request writes it again."""
USERNAME = re.compile(r"[a-z][a-z0-9._-]{2,31}")

HASHER = PasswordHasher()
"""argon2-cffi's defaults: Argon2id, 3 passes over 64 MiB, 4 lanes (RFC 9106 §4, second
recommended option). Tests swap in a cheap one."""

DEMO_ACCOUNTS = (
    ("asha", "Asha", Role.TRAINER, "Kasauti-Demo-Trainer"),
    ("ravi", "Ravi", Role.APPROVER, "Kasauti-Demo-Approver"),
)
"""Made by ``kasauti serve --demo-accounts`` and shown on its sign-in page, for demonstrations
only: anyone who can open the page can sign in as them."""


class AccountError(ValueError):
    """The request can't be done as asked. User-safe text."""


@dataclass(frozen=True, slots=True)
class Account:
    id: str
    username: str
    name: str
    role: Role

    def may(self, role: Role) -> bool:
        """Whether this account's role includes ``role``'s rights."""
        return RANK[self.role] >= RANK[role]


class AccountStore:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self._dummy = HASHER.hash(secrets.token_urlsafe(16))

    # -- accounts --------------------------------------------------------------------------------

    def create(self, username: str, name: str, password: str, role: Role) -> Account:
        username = username.strip().lower()
        name = " ".join(name.split())
        if not USERNAME.fullmatch(username):
            raise AccountError(
                "a username is 3 to 32 characters: lower-case letters, digits, '.', '_' or '-', "
                "starting with a letter"
            )
        if not name or len(name) > NAME_LIMIT:
            raise AccountError(f"a name is 1 to {NAME_LIMIT} characters")
        check_password(password, username)
        account = Account(str(uuid.uuid4()), username, name, role)
        try:
            with self.engine.begin() as conn:
                conn.execute(
                    insert(accounts).values(
                        id=account.id,
                        username=username,
                        name=name,
                        password_hash=HASHER.hash(password),
                        role=role,
                        created_at=utcnow(),
                        failed_logins=0,
                    )
                )
        except IntegrityError:
            raise AccountError(f"the username {username!r} is taken") from None
        return account

    def get(self, username: str) -> Account | None:
        with self.engine.connect() as conn:
            row = conn.execute(
                select(accounts).where(accounts.c.username == username.strip().lower())
            ).first()
        return _account(row) if row else None

    def count(self) -> int:
        with self.engine.connect() as conn:
            return int(conn.execute(select(func.count()).select_from(accounts)).scalar_one())

    def set_role(self, username: str, role: Role) -> Account:
        with self.engine.begin() as conn:
            done = conn.execute(
                update(accounts).where(accounts.c.username == username.lower()).values(role=role)
            )
        if done.rowcount != 1:
            raise AccountError(f"no account {username!r}")
        found = self.get(username)
        if found is None:  # deleted between the update and this read
            raise AccountError(f"no account {username!r}")
        return found

    def ensure_demo(self) -> None:
        """The demonstration accounts, with their published passwords, if they aren't there."""
        for username, name, role, password in DEMO_ACCOUNTS:
            if self.get(username) is None:
                self.create(username, name, password, role)

    # -- signing in ------------------------------------------------------------------------------

    def verify(self, username: str, password: str, now: dt.datetime | None = None) -> Account:
        """The account, if the password is right and it isn't locked; else :class:`AccountError`."""
        now = now or utcnow()
        wrong = AccountError("wrong username or password")
        with self.engine.connect() as conn:
            row = conn.execute(
                select(accounts).where(accounts.c.username == username.strip().lower())
            ).first()
        if row is None:
            _check(self._dummy, password)  # the same work as a real account: no timing tell
            raise wrong
        if row.locked_until is not None and row.locked_until > now:
            minutes = max(1, round((row.locked_until - now).total_seconds() / 60))
            raise AccountError(
                f"too many wrong passwords: this account is locked for {minutes} more minute(s)"
            )
        if not _check(row.password_hash, password):
            failures = row.failed_logins + 1
            locked = failures >= MAX_FAILURES
            with self.engine.begin() as conn:
                conn.execute(
                    update(accounts)
                    .where(accounts.c.id == row.id)
                    .values(
                        failed_logins=0 if locked else failures,
                        locked_until=now + LOCKOUT if locked else None,
                    )
                )
            raise wrong
        values: dict[str, object] = {"failed_logins": 0, "locked_until": None}
        if HASHER.check_needs_rehash(row.password_hash):
            values["password_hash"] = HASHER.hash(password)
        with self.engine.begin() as conn:
            conn.execute(update(accounts).where(accounts.c.id == row.id).values(**values))
        return _account(row)

    def start_session(self, account: Account, now: dt.datetime | None = None) -> str:
        """A new session's token, for the cookie. Only its hash is stored."""
        now = now or utcnow()
        token = secrets.token_urlsafe(32)
        with self.engine.begin() as conn:
            conn.execute(
                insert(sessions).values(
                    id=_digest(token),
                    account_id=account.id,
                    created_at=now,
                    seen_at=now,
                    expires_at=now + LIFETIME,
                )
            )
        return token

    def session(self, token: str, now: dt.datetime | None = None) -> Account | None:
        """The account a token signs in, or None if it is unknown, idle too long or expired."""
        now = now or utcnow()
        sid = _digest(token)
        with self.engine.connect() as conn:
            row = conn.execute(
                select(accounts, sessions.c.seen_at, sessions.c.expires_at)
                .join(sessions, sessions.c.account_id == accounts.c.id)
                .where(sessions.c.id == sid)
            ).first()
        if row is None:
            return None
        if row.expires_at <= now or row.seen_at + IDLE <= now:
            self.end_session(token)
            return None
        if row.seen_at + SEEN_EVERY <= now:
            with self.engine.begin() as conn:
                conn.execute(update(sessions).where(sessions.c.id == sid).values(seen_at=now))
        return _account(row)

    def end_session(self, token: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(delete(sessions).where(sessions.c.id == _digest(token)))

    def housekeep(self, now: dt.datetime | None = None) -> int:
        """Delete sessions that have ended; returns how many."""
        now = now or utcnow()
        with self.engine.begin() as conn:
            done = conn.execute(
                delete(sessions).where(
                    (sessions.c.expires_at <= now) | (sessions.c.seen_at <= now - IDLE)
                )
            )
        return done.rowcount


def check_password(password: str, username: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise AccountError(f"a password is at least {MIN_PASSWORD} characters; a phrase is easiest")
    if len(password) > MAX_PASSWORD:
        raise AccountError(f"a password is at most {MAX_PASSWORD} characters")
    if username in password.lower() or len(set(password)) < 4:
        raise AccountError("that password is too easy to guess")


def _check(hashed: str, password: str) -> bool:
    try:
        return HASHER.verify(hashed, password)
    except (VerificationError, InvalidHashError):
        return False


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _account(row: object) -> Account:
    return Account(row.id, row.username, row.name, Role(row.role))  # type: ignore[attr-defined]
