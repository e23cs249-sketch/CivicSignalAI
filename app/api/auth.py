from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app import database
from app.services.team_auth import normalize_email, hash_password, verify_password

router = APIRouter(prefix="/api/auth/team", tags=["team-auth"])
citizen_router = APIRouter(prefix="/api/auth/citizen", tags=["citizen-auth"])
SESSION_COOKIE = "civicsignal_team_session"
CITIZEN_SESSION_COOKIE = "civicsignal_citizen_session"
SESSION_SECONDS = 8 * 60 * 60
CITIZEN_SESSION_SECONDS = 8 * 60 * 60
LOGIN_WINDOW_SECONDS = 15 * 60
MAX_LOGIN_ATTEMPTS = 5
DUMMY_PASSWORD_HASH = hash_password("not-a-valid-team-password")


class TeamLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        try:
            return normalize_email(value)
        except ValueError as exception:
            raise ValueError(str(exception)) from exception


class CitizenSignupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    phone: str = Field(min_length=6, max_length=40)
    password: str = Field(min_length=12, max_length=1024)
    confirm_password: str = Field(min_length=12, max_length=1024)
    accepted_terms: bool = Field(default=False)

    @field_validator("full_name", "phone")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("This field cannot be blank.")
        return value.strip()

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        try:
            return normalize_email(value)
        except ValueError as exception:
            raise ValueError(str(exception)) from exception


class CitizenLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        try:
            return normalize_email(value)
        except ValueError as exception:
            raise ValueError(str(exception)) from exception


def session_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def current_team_user(request: Request) -> dict[str, str] | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    session = database.get_team_session(session_fingerprint(token), int(time.time()))
    if session is None:
        return None
    return {"email": str(session["email"])}


def citizen_session_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def current_citizen_user(request: Request) -> dict[str, str] | None:
    token = request.cookies.get(CITIZEN_SESSION_COOKIE)
    if not token:
        return None
    session = database.get_citizen_session(citizen_session_fingerprint(token), int(time.time()))
    if session is None:
        return None
    return {"id": str(session["user_id"]), "email": str(session["email"])}


def require_citizen_user(request: Request) -> dict[str, str]:
    user = current_citizen_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Citizen authentication is required.")
    return user


def require_team_user(request: Request) -> dict[str, str]:
    user = current_team_user(request)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Team authentication is required.",
            headers={"WWW-Authenticate": "Cookie"},
        )
    return user


def require_same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    expected = str(request.base_url).rstrip("/")
    if origin and origin.rstrip("/") != expected:
        raise HTTPException(status_code=403, detail="Cross-origin request rejected.")
    if request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(status_code=403, detail="Cross-origin request rejected.")


def _remote_address(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _secure_cookie(request: Request) -> bool:
    configured = os.getenv("CIVICSIGNAL_COOKIE_SECURE")
    if configured is not None:
        return configured.strip().lower() in {"1", "true", "yes", "on"}
    return request.url.scheme == "https"


@router.post("/login")
def team_login(payload: TeamLoginRequest, request: Request, response: Response) -> dict[str, Any]:
    now = int(time.time())
    remote_addr = _remote_address(request)
    if database.count_recent_team_login_attempts(remote_addr, now - LOGIN_WINDOW_SECONDS) >= MAX_LOGIN_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many sign-in attempts. Try again in 15 minutes.")

    user = database.get_team_user(payload.email)
    encoded_hash = str(user["password_hash"]) if user else DUMMY_PASSWORD_HASH
    valid_password = verify_password(payload.password, encoded_hash)
    if user is None or not bool(user["is_active"]) or not valid_password:
        database.record_team_login_attempt(remote_addr, now)
        raise HTTPException(status_code=401, detail="Work email or password is incorrect.")

    database.clear_team_login_attempts(remote_addr)
    token = secrets.token_urlsafe(32)
    expires_at = now + SESSION_SECONDS
    database.create_team_session(session_fingerprint(token), payload.email, expires_at)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_SECONDS,
        httponly=True,
        secure=_secure_cookie(request),
        samesite="strict",
        path="/",
    )
    return {"authenticated": True, "email": payload.email}


@router.get("/me")
def team_session(user: dict[str, str] = Depends(require_team_user)) -> dict[str, object]:
    return {"authenticated": True, "email": user["email"]}


@router.post("/logout")
def team_logout(request: Request, response: Response, _: dict[str, str] = Depends(require_team_user)) -> dict[str, bool]:
    require_same_origin(request)
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        database.delete_team_session(session_fingerprint(token))
    response.delete_cookie(
        key=SESSION_COOKIE,
        httponly=True,
        secure=_secure_cookie(request),
        samesite="strict",
        path="/",
    )
    return {"authenticated": False}


@citizen_router.post("/register")
def citizen_register(payload: CitizenSignupRequest, request: Request, response: Response) -> dict[str, Any]:
    require_same_origin(request)
    if not payload.accepted_terms:
        raise HTTPException(status_code=400, detail="You must accept the terms and privacy policy.")
    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")

    normalized_email = normalize_email(payload.email)
    existing = database.get_citizen_user_by_email(normalized_email)
    if existing is not None:
        raise HTTPException(status_code=409, detail="An account already exists for this email.")

    password_hash = hash_password(payload.password)
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    user_id = secrets.token_urlsafe(16)
    try:
        database.create_citizen_user(
            user_id,
            payload.full_name,
            normalized_email,
            payload.phone,
            password_hash,
            True,
            created_at,
        )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="An account already exists for this email.") from None

    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + CITIZEN_SESSION_SECONDS
    database.create_citizen_session(citizen_session_fingerprint(token), user_id, normalized_email, expires_at)
    response.set_cookie(
        key=CITIZEN_SESSION_COOKIE,
        value=token,
        max_age=CITIZEN_SESSION_SECONDS,
        httponly=True,
        secure=_secure_cookie(request),
        samesite="strict",
        path="/",
    )
    return {"authenticated": True, "email": normalized_email, "full_name": payload.full_name}


@citizen_router.post("/login")
def citizen_login(payload: CitizenLoginRequest, request: Request, response: Response) -> dict[str, Any]:
    require_same_origin(request)
    now = int(time.time())
    remote_addr = _remote_address(request)
    if database.count_recent_team_login_attempts(remote_addr, now - LOGIN_WINDOW_SECONDS) >= MAX_LOGIN_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many sign-in attempts. Try again in 15 minutes.")

    normalized_email = normalize_email(payload.email)
    user = database.get_citizen_user_by_email(normalized_email)
    encoded_hash = str(user["password_hash"]) if user else DUMMY_PASSWORD_HASH
    valid_password = verify_password(payload.password, encoded_hash)
    if user is None or not bool(user["is_active"]) or not valid_password:
        database.record_team_login_attempt(remote_addr, now)
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")

    database.clear_team_login_attempts(remote_addr)
    token = secrets.token_urlsafe(32)
    expires_at = now + CITIZEN_SESSION_SECONDS
    database.create_citizen_session(citizen_session_fingerprint(token), str(user["id"]), normalized_email, expires_at)
    response.set_cookie(
        key=CITIZEN_SESSION_COOKIE,
        value=token,
        max_age=CITIZEN_SESSION_SECONDS,
        httponly=True,
        secure=_secure_cookie(request),
        samesite="strict",
        path="/",
    )
    return {"authenticated": True, "email": normalized_email, "full_name": str(user["full_name"])}


@citizen_router.get("/me")
def citizen_session(user: dict[str, str] = Depends(require_citizen_user)) -> dict[str, object]:
    return {"authenticated": True, "email": user["email"], "id": user["id"]}


@citizen_router.post("/logout")
def citizen_logout(request: Request, response: Response, _: dict[str, str] = Depends(require_citizen_user)) -> dict[str, bool]:
    require_same_origin(request)
    token = request.cookies.get(CITIZEN_SESSION_COOKIE)
    if token:
        database.delete_citizen_session(citizen_session_fingerprint(token))
    response.delete_cookie(
        key=CITIZEN_SESSION_COOKIE,
        httponly=True,
        secure=_secure_cookie(request),
        samesite="strict",
        path="/",
    )
    return {"authenticated": False}