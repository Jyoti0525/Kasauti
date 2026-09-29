"""Sign-in, sign-up and sign-out (PLAN §17; TODO M5.03-M5.05).

    GET    /api/auth/options     whether sign-up is open, and the demo accounts if there are any
    POST   /api/auth/signup      a new account (role: auditor), signed in
    POST   /api/auth/login       signed in
    POST   /api/auth/logout      signed out
    GET    /api/auth/me          who is signed in

Every other route under ``/api`` except ``/api/health`` needs a session (:func:`signed_in`), and
one that changes something needs a role that may (:func:`may_change`). The session travels in
an HttpOnly, SameSite=Strict cookie, so page scripts can't read it and other sites' pages can't
send it; the cross-site checks of :mod:`kasauti.api.app` still apply to every change,
signing in included.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from kasauti.accounts import DEMO_ACCOUNTS, Account, AccountError, AccountStore, Role
from kasauti.accounts.store import LIFETIME, MAX_PASSWORD, MIN_PASSWORD

router = APIRouter(prefix="/api/auth", tags=["auth"])
COOKIE = "kasauti_session"
UNSAFE = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class AccountOut(_Model):
    username: str
    name: str
    role: Role


class DemoOut(_Model):
    username: str
    name: str
    role: Role
    password: str


class OptionsOut(_Model):
    signup: bool
    min_password: int
    demo: tuple[DemoOut, ...]


class LoginIn(_Model):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD)


class SignupIn(_Model):
    username: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD)


def _store(request: Request) -> AccountStore:
    store: AccountStore = request.app.state.accounts
    return store


def _out(a: Account) -> AccountOut:
    return AccountOut(username=a.username, name=a.name, role=a.role)


async def signed_in(request: Request) -> Account:
    """The signed-in account, or 401. Routers that need a session depend on this."""
    token = request.cookies.get(COOKIE)
    account = await run_in_threadpool(_store(request).session, token) if token else None
    if account is None:
        raise HTTPException(401, "sign in first")
    request.state.account = account
    return account


def needs(role: Role, *, changes_only: bool = True):  # type: ignore[no-untyped-def]
    """A dependency: the signed-in account must hold ``role`` (for requests that change
    something only, with ``changes_only``)."""

    async def check(request: Request, account: Annotated[Account, Depends(signed_in)]) -> Account:
        if (not changes_only or request.method in UNSAFE) and not account.may(role):
            raise HTTPException(403, f"this needs the {role.value} role; you are {account.role}")
        return account

    return check


def _start(request: Request, response: Response, account: Account) -> AccountOut:
    token = _store(request).start_session(account)
    response.set_cookie(
        COOKIE,
        token,
        max_age=int(LIFETIME.total_seconds()),
        path="/",
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
    )
    return _out(account)


@router.get("/options")
async def options(request: Request) -> OptionsOut:
    demo = request.app.state.demo_accounts
    return OptionsOut(
        signup=request.app.state.signup,
        min_password=MIN_PASSWORD,
        demo=tuple(DemoOut(username=u, name=n, role=r, password=p) for u, n, r, p in DEMO_ACCOUNTS)
        if demo
        else (),
    )


@router.post("/login", responses={401: {}})
async def login(body: LoginIn, request: Request, response: Response) -> AccountOut:
    store = _store(request)
    try:
        account = await run_in_threadpool(store.verify, body.username, body.password)
    except AccountError as err:
        raise HTTPException(401, str(err)) from None
    return await run_in_threadpool(_start, request, response, account)


@router.post("/signup", status_code=201, responses={403: {}, 409: {}})
async def signup(body: SignupIn, request: Request, response: Response) -> AccountOut:
    if not request.app.state.signup:
        raise HTTPException(403, "sign-up is closed on this server: ask an administrator")
    store = _store(request)
    try:
        account = await run_in_threadpool(
            store.create, body.username, body.name, body.password, Role.AUDITOR
        )
    except AccountError as err:
        raise HTTPException(409, str(err)) from None
    return await run_in_threadpool(_start, request, response, account)


@router.post("/logout", status_code=204)
async def logout(request: Request) -> Response:
    token = request.cookies.get(COOKIE)
    if token:
        await run_in_threadpool(_store(request).end_session, token)
    response = Response(status_code=204)
    response.delete_cookie(COOKIE, path="/", httponly=True, samesite="strict")
    return response


@router.get("/me", responses={401: {}})
async def me(account: Annotated[Account, Depends(signed_in)]) -> AccountOut:
    return _out(account)
