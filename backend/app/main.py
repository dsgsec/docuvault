import hmac
import hashlib
import json
import logging
import os
import re
import secrets
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from .database import Base, SessionLocal, engine
from .models import (
    AuditEvent,
    Document,
    DocumentShare,
    Invitation,
    Membership,
    Organization,
    User,
    UserSession,
    utcnow,
)


logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("docuvault.security")
password_hasher = PasswordHasher()
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
APP_ENVIRONMENT = os.getenv("APP_ENV", "development")
PSEUDONYM_KEY = os.getenv("AUDIT_PSEUDONYM_KEY", "local-development-audit-pseudonym-key")
FILE_ROOT = Path(os.getenv("FILE_STORAGE_PATH", "/var/lib/docuvault/files")).resolve()
EVENT_QUEUE_KEY = "docuvault.security_events"
AUTH_LIMIT_WINDOW_SECONDS = 60
AUTH_LIMIT_MAX_REQUESTS = 15
auth_rate_windows: dict[tuple[str, str], tuple[float, int]] = {}
MAX_UPLOAD_SIZE = 15 * 1024 * 1024
MAX_MULTIPART_OVERHEAD = 128 * 1024
ALLOWED_TYPES = {
    ".pdf": ("application/pdf", b"%PDF-"),
    ".txt": ("text/plain", None),
    ".png": ("image/png", b"\x89PNG\r\n\x1a\n"),
    ".jpg": ("image/jpeg", b"\xff\xd8\xff"),
    ".jpeg": ("image/jpeg", b"\xff\xd8\xff"),
}


EVENT_SEVERITY = {
    "auth.register.success": "info",
    "auth.login.success": "info",
    "auth.login.failure": "medium",
    "auth.logout": "info",
    "auth.session.created": "info",
    "auth.session.revoked": "info",
    "auth.session.expired": "info",
    "auth.password.changed": "info",
    "auth.password.change.failure": "medium",
    "auth.token.invalid": "medium",
    "access.denied": "medium",
    "access.cross_tenant.denied": "high",
    "access.role_denied": "medium",
    "access.resource_not_found": "low",
    "organization.created": "info",
    "organization.member.invited": "info",
    "organization.member.invitation.accepted": "info",
    "organization.member.removed": "info",
    "organization.member.role_changed": "info",
    "document.viewed": "info",
    "document.downloaded": "info",
    "document.updated": "info",
    "document.deleted": "info",
    "document.uploaded": "info",
    "document.upload.rejected": "low",
    "sharing.created": "info",
    "sharing.updated": "info",
    "sharing.revoked": "info",
    "sharing.external_attempt": "medium",
    "api.rate_limit.exceeded": "medium",
    "api.validation.failed": "low",
    "api.upload.limit_exceeded": "medium",
    "api.request.rejected": "medium",
}
EVENT_OUTCOMES = {"success", "failure", "denied", "error"}


@sqlalchemy_event.listens_for(Session, "after_commit")
def emit_committed_security_events(session: Session):
    for event in session.info.pop(EVENT_QUEUE_KEY, []):
        logger.info(json.dumps(event, ensure_ascii=False, separators=(",", ":")))


@sqlalchemy_event.listens_for(Session, "after_rollback")
def discard_rolled_back_security_events(session: Session):
    session.info.pop(EVENT_QUEUE_KEY, None)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if APP_ENVIRONMENT == "production" and not os.getenv("AUDIT_PSEUDONYM_KEY"):
        raise RuntimeError("AUDIT_PSEUDONYM_KEY doit être défini en production")
    FILE_ROOT.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    if os.getenv("SEED_DEMO", "false").lower() == "true":
        seed_demo()
    yield


app = FastAPI(title="DocuVault API", version="1.0.0", lifespan=lifespan)


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class RegisterInput(Credentials):
    name: str = Field(min_length=1, max_length=120)


class OrganizationInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)


class ProfileInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class PasswordInput(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class DocumentInput(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)


class ShareInput(BaseModel):
    user_id: str
    permission: str


class InviteInput(BaseModel):
    email: EmailStr
    role: str = "member"


class RoleInput(BaseModel):
    role: str


class AcceptInvitationInput(BaseModel):
    token: str = Field(min_length=32, max_length=128)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


Db = Annotated[Session, Depends(get_db)]


@app.middleware("http")
async def correlation_id(request: Request, call_next):
    request.state.request_id = str(uuid.uuid4())
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        expected_origin = f"{request.url.scheme}://{request.headers.get('host', '')}"
        cross_site = request.headers.get("sec-fetch-site") == "cross-site"
        if cross_site or (origin and origin.rstrip("/") != expected_origin.rstrip("/")):
            record_request_event(
                request, "api.request.rejected", "denied", 403,
                reason="cross_origin_request",
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "Origine de requête non autorisée"},
                headers={
                    "X-Request-ID": request.state.request_id,
                    "Cache-Control": "no-store",
                },
            )
    if request.method == "POST" and request.url.path in {"/auth/login", "/auth/register"}:
        if auth_rate_limited(request):
            record_request_event(
                request, "api.rate_limit.exceeded", "denied", 429,
                reason="authentication_attempt_limit",
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Trop de tentatives. Réessayez dans une minute."},
                headers={
                    "X-Request-ID": request.state.request_id,
                    "Cache-Control": "no-store",
                    "Retry-After": str(AUTH_LIMIT_WINDOW_SECONDS),
                },
            )
    if (
        request.method == "POST"
        and re.fullmatch(r"/organizations/[^/]+/documents", request.url.path)
    ):
        content_length = request.headers.get("content-length", "")
        if content_length.isdigit() and int(content_length) > MAX_UPLOAD_SIZE + MAX_MULTIPART_OVERHEAD:
            record_request_event(
                request, "api.upload.limit_exceeded", "denied", 413,
                reason="request_body_too_large", limit_bytes=MAX_UPLOAD_SIZE,
            )
            return JSONResponse(
                status_code=413,
                content={"detail": "Taille maximale : 15 Mo"},
                headers={
                    "X-Request-ID": request.state.request_id,
                    "Cache-Control": "no-store",
                },
            )
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["Cache-Control"] = "no-store"
    return response


def auth_rate_limited(request: Request) -> bool:
    now = time.monotonic()
    key = (request.client.host if request.client else "unknown", request.url.path)
    window_start, count = auth_rate_windows.get(key, (now, 0))
    if now - window_start >= AUTH_LIMIT_WINDOW_SECONDS:
        auth_rate_windows[key] = (now, 1)
        return False
    if count >= AUTH_LIMIT_MAX_REQUESTS:
        return True
    auth_rate_windows[key] = (window_start, count + 1)
    if len(auth_rate_windows) > 10_000:
        cutoff = now - AUTH_LIMIT_WINDOW_SECONDS
        for stale_key, (started, _) in list(auth_rate_windows.items()):
            if started < cutoff:
                del auth_rate_windows[stale_key]
    return False


def record_request_event(
    request: Request,
    event_type: str,
    outcome: str,
    status_code: int,
    **context,
):
    with SessionLocal() as db:
        audit(
            db, request, event_type, outcome,
            target_type="http_request", context=context, status_code=status_code,
        )
        db.commit()


def audit(
    db: Session,
    request: Request,
    event_type: str,
    outcome: str,
    actor_id: str | None = None,
    organization_id: str | None = None,
    resource_id: str | None = None,
    *,
    target_type: str | None = None,
    target_id: str | None = None,
    target_organization_id: str | None = None,
    actor_organization_id: str | None = None,
    context: dict | None = None,
    status_code: int | None = None,
    severity: str | None = None,
):
    if event_type not in EVENT_SEVERITY or outcome not in EVENT_OUTCOMES:
        raise ValueError("Événement de sécurité ou résultat non normalisé")

    timestamp = utcnow().isoformat(timespec="milliseconds").replace("+00:00", "Z")
    event_id = str(uuid.uuid4())
    target_organization_id = target_organization_id or organization_id
    target_id = target_id or resource_id
    if actor_organization_id is None and actor_id and organization_id:
        actor_membership = db.scalar(select(Membership).where(
            Membership.organization_id == organization_id,
            Membership.user_id == actor_id,
        ))
        if actor_membership:
            actor_organization_id = organization_id
    actor_membership = None
    if actor_id and actor_organization_id:
        actor_membership = db.scalar(select(Membership).where(
            Membership.organization_id == actor_organization_id,
            Membership.user_id == actor_id,
        ))
    if target_type is None:
        if event_type.startswith(("document.", "sharing.")):
            target_type = "document"
        elif event_type.startswith("organization."):
            target_type = "organization"
        elif event_type.startswith("auth."):
            target_type = "user"
    route = request.scope.get("route")
    route_template = getattr(route, "path", request.url.path)
    user_agent = request.headers.get("user-agent")
    event_payload = {
        "schema_version": "1.0",
        "timestamp": timestamp,
        "event_id": event_id,
        "event_type": event_type,
        "severity": severity or EVENT_SEVERITY[event_type],
        "outcome": outcome,
        "service": {
            "name": "docuvault-api",
            "environment": APP_ENVIRONMENT,
        },
        "actor": {
            "user_id": actor_id,
            "organization_id": actor_organization_id,
            "role": actor_membership.role if actor_membership else None,
        },
        "source": {
            "ip": request.client.host if request.client else None,
            "user_agent": user_agent[:512] if user_agent else None,
        },
        "target": {
            "type": target_type,
            "id": target_id,
            "organization_id": target_organization_id,
        },
        "http": {
            "request_id": request.state.request_id,
            "method": request.method,
            "route": route_template,
            "status_code": status_code or (403 if outcome == "denied" else 200),
        },
        "context": context or {},
    }
    audit_row = AuditEvent(
        id=event_id,
        event_type=event_type,
        actor_id=actor_id,
        organization_id=target_organization_id,
        resource_id=target_id,
        result=outcome,
        source_ip=request.client.host if request.client else None,
        request_id=request.state.request_id,
    )
    db.add(audit_row)
    db.info.setdefault(EVENT_QUEUE_KEY, []).append(event_payload)


def get_current_user(request: Request, db: Db) -> User:
    token = request.cookies.get("docuvault_session")
    if not token:
        raise HTTPException(status_code=401, detail="Authentification requise")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    session = db.get(UserSession, token_hash)
    if not session:
        audit(
            db, request, "auth.token.invalid", "denied",
            target_type="session", context={"reason": "unknown_session"},
            status_code=401,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Session invalide ou expirée")
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < utcnow():
        audit(
            db, request, "auth.session.expired", "denied",
            actor_id=session.user_id, target_type="session",
            context={"reason": "session_expired"}, status_code=401,
        )
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=401, detail="Session invalide ou expirée")
    user = db.get(User, session.user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Session invalide ou expirée")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_membership(
    db: Session, organization_id: str, user: User, request: Request | None = None,
) -> Membership:
    membership = db.scalar(select(Membership).where(
        Membership.organization_id == organization_id,
        Membership.user_id == user.id,
    ))
    if membership is None:
        organization = db.get(Organization, organization_id)
        if request and organization:
            audit(
                db, request, "access.cross_tenant.denied", "denied",
                actor_id=user.id, organization_id=organization_id,
                target_type="organization", target_id=organization_id,
                context={"reason": "cross_tenant_access"},
                status_code=404,
            )
            db.commit()
        raise HTTPException(status_code=404, detail="Organisation introuvable")
    return membership


def require_manager(membership: Membership, db: Session, request: Request, user: User):
    if membership.role not in ("owner", "admin"):
        audit(
            db, request, "access.role_denied", "denied",
            actor_id=user.id, organization_id=membership.organization_id,
            actor_organization_id=membership.organization_id,
            target_type="organization", target_id=membership.organization_id,
            context={"reason": "manager_role_required"},
            status_code=403,
        )
        db.commit()
        raise HTTPException(status_code=403, detail="Permission insuffisante")


def doc_access(db: Session, document: Document, user: User, write: bool = False) -> bool:
    membership = db.scalar(select(Membership).where(
        Membership.organization_id == document.organization_id,
        Membership.user_id == user.id,
    ))
    if membership is None:
        return False
    if membership.role in ("owner", "admin") or document.owner_id == user.id:
        return True
    share = db.scalar(select(DocumentShare).where(
        DocumentShare.document_id == document.id,
        DocumentShare.user_id == user.id,
    ))
    return bool(share and (not write or share.permission == "edit"))


def require_document(
    db: Session, document_id: str, user: User, request: Request, write: bool = False,
) -> Document:
    document = db.get(Document, document_id)
    if document is None:
        raise HTTPException(status_code=404, detail="Document introuvable")
    if not doc_access(db, document, user, write):
        membership = db.scalar(select(Membership).where(
            Membership.organization_id == document.organization_id,
            Membership.user_id == user.id,
        ))
        cross_tenant = membership is None
        audit(
            db, request,
            "access.cross_tenant.denied" if cross_tenant else "access.denied",
            "denied",
            actor_id=user.id, organization_id=document.organization_id,
            resource_id=document.id, target_type="document",
            actor_organization_id=None if cross_tenant else document.organization_id,
            context={
                "reason": "cross_tenant_access" if cross_tenant else "document_permission_required",
                "action": request.method,
            },
            status_code=404,
        )
        db.commit()
        raise HTTPException(status_code=404, detail="Document introuvable")
    return document


def user_view(user: User):
    return {"id": user.id, "email": user.email, "name": user.name}


def organization_view(db: Session, organization: Organization, user: User):
    membership = db.scalar(select(Membership).where(
        Membership.organization_id == organization.id,
        Membership.user_id == user.id,
    ))
    return {"id": organization.id, "name": organization.name, "role": membership.role}


def document_view(db: Session, document: Document, user: User):
    owner = db.get(User, document.owner_id)
    share = db.scalar(select(DocumentShare).where(
        DocumentShare.document_id == document.id,
        DocumentShare.user_id == user.id,
    ))
    membership = db.scalar(select(Membership).where(
        Membership.organization_id == document.organization_id,
        Membership.user_id == user.id,
    ))
    permission = "owner" if document.owner_id == user.id else (
        "admin" if membership and membership.role in ("owner", "admin")
        else (share.permission if share else "read")
    )
    return {
        "id": document.id,
        "organization_id": document.organization_id,
        "owner_id": document.owner_id,
        "owner_name": owner.name if owner else "Utilisateur",
        "title": document.title,
        "description": document.description,
        "original_name": document.original_name,
        "content_type": document.content_type,
        "size": document.size,
        "created_at": document.created_at.isoformat(),
        "updated_at": document.updated_at.isoformat(),
        "permission": permission,
    }


def seed_demo():
    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.email == "demo@docuvault.example.com"))
        if existing:
            return
        user = User(
            id=str(uuid.uuid4()),
            email="demo@docuvault.example.com",
            name="Camille Martin",
            password_hash=password_hasher.hash("DemoVault2026!"),
        )
        organization = Organization(id=str(uuid.uuid4()), name="Atelier Horizon")
        db.add_all([user, organization])
        db.flush()
        db.add(Membership(
            id=str(uuid.uuid4()), organization_id=organization.id,
            user_id=user.id, role="owner",
        ))
        content = b"Document de demonstration DocuVault.\nDonnees fictives uniquement.\n"
        storage_key = f"{uuid.uuid4()}.txt"
        (FILE_ROOT / storage_key).write_bytes(content)
        db.add(Document(
            id=str(uuid.uuid4()), organization_id=organization.id, owner_id=user.id,
            title="Guide de bienvenue", description="Document exemple de l'espace de travail.",
            original_name="guide-bienvenue.txt", storage_key=storage_key,
            content_type="text/plain", size=len(content),
        ))
        db.commit()


@app.get("/health")
def health():
    return {"status": "ok"}


def issue_session(db: Session, response: Response, user: User):
    token = secrets.token_urlsafe(32)
    db.add(UserSession(
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        user_id=user.id,
        expires_at=utcnow() + timedelta(hours=8),
    ))
    response.set_cookie(
        "docuvault_session", token, httponly=True, secure=COOKIE_SECURE,
        samesite="lax", max_age=8 * 60 * 60, path="/",
    )


def pseudonymize_account(email: str) -> str:
    return hmac.new(
        PSEUDONYM_KEY.encode(),
        email.strip().lower().encode(),
        hashlib.sha256,
    ).hexdigest()


@app.post("/auth/register", status_code=201)
def register(body: RegisterInput, request: Request, response: Response, db: Db):
    email = body.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Cette adresse e-mail est déjà utilisée")
    user = User(
        id=str(uuid.uuid4()), email=email, name=body.name.strip(),
        password_hash=password_hasher.hash(body.password),
    )
    db.add(user)
    db.flush()
    issue_session(db, response, user)
    audit(
        db, request, "auth.register.success", "success",
        actor_id=user.id, target_type="user", target_id=user.id,
        status_code=201,
    )
    audit(
        db, request, "auth.session.created", "success",
        actor_id=user.id, target_type="session", status_code=201,
    )
    db.commit()
    return {"user": user_view(user)}


@app.post("/auth/login")
def login(body: Credentials, request: Request, response: Response, db: Db):
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    try:
        valid = bool(user and password_hasher.verify(user.password_hash, body.password))
    except VerifyMismatchError:
        valid = False
    if not valid:
        audit(
            db, request, "auth.login.failure", "failure",
            actor_id=user.id if user else None,
            target_type="user" if user else "account",
            context={
                "reason": "invalid_credentials",
                "account_ref": pseudonymize_account(body.email),
            },
            status_code=401,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Adresse e-mail ou mot de passe incorrect")
    issue_session(db, response, user)
    audit(
        db, request, "auth.login.success", "success",
        actor_id=user.id, target_type="user", target_id=user.id,
    )
    audit(
        db, request, "auth.session.created", "success",
        actor_id=user.id, target_type="session",
    )
    db.commit()
    return {"user": user_view(user)}


@app.post("/auth/logout")
def logout(request: Request, response: Response, db: Db, user: CurrentUser):
    token = request.cookies["docuvault_session"]
    session = db.get(UserSession, hashlib.sha256(token.encode()).hexdigest())
    if session:
        db.delete(session)
    audit(
        db, request, "auth.logout", "success",
        actor_id=user.id, target_type="user", target_id=user.id,
    )
    audit(
        db, request, "auth.session.revoked", "success",
        actor_id=user.id, target_type="session",
        context={"reason": "user_logout"},
    )
    db.commit()
    response.delete_cookie("docuvault_session", path="/", httponly=True, secure=COOKIE_SECURE, samesite="lax")
    return {"status": "ok"}


@app.get("/auth/me")
def me(user: CurrentUser):
    return {"user": user_view(user)}


@app.patch("/users/me")
def update_profile(body: ProfileInput, user: CurrentUser, db: Db):
    user.name = body.name.strip()
    db.commit()
    return {"user": user_view(user)}


@app.post("/users/me/password")
def change_password(body: PasswordInput, request: Request, user: CurrentUser, db: Db):
    try:
        valid = password_hasher.verify(user.password_hash, body.current_password)
    except VerifyMismatchError:
        valid = False
    if not valid:
        audit(
            db, request, "auth.password.change.failure", "failure",
            actor_id=user.id, target_type="user", target_id=user.id,
            context={"reason": "current_password_mismatch"}, status_code=400,
        )
        db.commit()
        raise HTTPException(status_code=400, detail="Mot de passe actuel incorrect")
    user.password_hash = password_hasher.hash(body.new_password)
    current_hash = hashlib.sha256(request.cookies["docuvault_session"].encode()).hexdigest()
    revoked_count = db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.token_hash != current_hash,
    ).delete(synchronize_session=False)
    audit(
        db, request, "auth.password.changed", "success",
        actor_id=user.id, target_type="user", target_id=user.id,
    )
    if revoked_count:
        audit(
            db, request, "auth.session.revoked", "success",
            actor_id=user.id, target_type="session",
            context={"reason": "password_changed", "revoked_count": revoked_count},
        )
    db.commit()
    return {"status": "ok"}


@app.get("/organizations")
def list_organizations(user: CurrentUser, db: Db):
    organizations = db.scalars(
        select(Organization).join(Membership).where(Membership.user_id == user.id)
    ).all()
    return {"organizations": [organization_view(db, org, user) for org in organizations]}


@app.post("/organizations", status_code=201)
def create_organization(body: OrganizationInput, request: Request, user: CurrentUser, db: Db):
    organization = Organization(id=str(uuid.uuid4()), name=body.name.strip())
    db.add(organization)
    db.flush()
    db.add(Membership(
        id=str(uuid.uuid4()), organization_id=organization.id, user_id=user.id, role="owner",
    ))
    audit(
        db, request, "organization.created", "success",
        user.id, organization.id, organization.id,
        target_type="organization", target_id=organization.id,
        actor_organization_id=organization.id, status_code=201,
    )
    db.commit()
    return organization_view(db, organization, user)


@app.get("/organizations/{organization_id}/members")
def list_members(organization_id: str, request: Request, user: CurrentUser, db: Db):
    membership = require_membership(db, organization_id, user, request)
    rows = db.execute(
        select(Membership, User).join(User, User.id == Membership.user_id)
        .where(Membership.organization_id == organization_id)
        .order_by(Membership.created_at)
    ).all()
    return {"members": [
        {"id": m.user_id, "email": u.email, "name": u.name, "role": m.role}
        for m, u in rows
    ], "my_role": membership.role}


@app.post("/organizations/{organization_id}/invitations", status_code=201)
def invite_member(organization_id: str, body: InviteInput, request: Request, user: CurrentUser, db: Db):
    membership = require_membership(db, organization_id, user, request)
    require_manager(membership, db, request, user)
    if body.role not in ("member", "admin") or (body.role == "admin" and membership.role != "owner"):
        audit(
            db, request, "access.role_denied", "denied",
            actor_id=user.id, organization_id=organization_id,
            actor_organization_id=organization_id,
            target_type="organization", target_id=organization_id,
            context={"reason": "inviting_admin_requires_owner"},
            status_code=403,
        )
        db.commit()
        raise HTTPException(status_code=403, detail="Rôle d'invitation non autorisé")
    email = body.email.lower()
    if db.scalar(select(Membership).join(User).where(
        Membership.organization_id == organization_id, User.email == email
    )):
        raise HTTPException(status_code=409, detail="Cet utilisateur est déjà membre")
    raw_token = secrets.token_urlsafe(32)
    invitation = Invitation(
        id=str(uuid.uuid4()), organization_id=organization_id, email=email, role=body.role,
        token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
        expires_at=utcnow() + timedelta(days=7),
    )
    db.add(invitation)
    audit(
        db, request, "organization.member.invited", "success",
        user.id, organization_id, invitation.id,
        target_type="invitation", target_id=invitation.id,
        actor_organization_id=organization_id,
        context={"invited_role": body.role}, status_code=201,
    )
    db.commit()
    return {"invitation_id": invitation.id, "token": raw_token, "email": email, "expires_at": invitation.expires_at.isoformat()}


@app.post("/invitations/accept")
def accept_invitation(body: AcceptInvitationInput, request: Request, user: CurrentUser, db: Db):
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    invitation = db.scalar(select(Invitation).where(Invitation.token_hash == token_hash))
    if not invitation or invitation.accepted_at:
        audit(
            db, request, "access.denied", "denied", actor_id=user.id,
            target_type="invitation", context={"reason": "invalid_or_used_invitation"},
            status_code=404,
        )
        db.commit()
        raise HTTPException(status_code=404, detail="Invitation invalide ou expirée")
    expires_at = invitation.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < utcnow():
        audit(
            db, request, "access.denied", "denied", actor_id=user.id,
            organization_id=invitation.organization_id, resource_id=invitation.id,
            target_type="invitation", actor_organization_id=invitation.organization_id,
            context={"reason": "invitation_expired"}, status_code=404,
        )
        db.commit()
        raise HTTPException(status_code=404, detail="Invitation invalide ou expirée")
    if invitation.email.lower() != user.email.lower():
        audit(
            db, request, "access.denied", "denied", actor_id=user.id,
            organization_id=invitation.organization_id, resource_id=invitation.id,
            target_type="invitation",
            context={"reason": "invitation_email_mismatch"}, status_code=403,
        )
        db.commit()
        raise HTTPException(status_code=403, detail="Cette invitation est destinée à une autre adresse")
    existing = db.scalar(select(Membership).where(
        Membership.organization_id == invitation.organization_id, Membership.user_id == user.id,
    ))
    if not existing:
        db.add(Membership(
            id=str(uuid.uuid4()), organization_id=invitation.organization_id,
            user_id=user.id, role=invitation.role,
        ))
    invitation.accepted_at = utcnow()
    audit(
        db, request, "organization.member.invitation.accepted", "success",
        user.id, invitation.organization_id, invitation.id,
        target_type="invitation", target_id=invitation.id,
        actor_organization_id=invitation.organization_id,
    )
    db.commit()
    return {"status": "ok", "organization_id": invitation.organization_id}


@app.patch("/organizations/{organization_id}/members/{member_id}")
def change_member_role(organization_id: str, member_id: str, body: RoleInput, request: Request, user: CurrentUser, db: Db):
    actor_membership = require_membership(db, organization_id, user, request)
    require_manager(actor_membership, db, request, user)
    role = body.role
    if role not in ("admin", "member"):
        raise HTTPException(status_code=422, detail="Rôle invalide")
    target = db.scalar(select(Membership).where(
        Membership.organization_id == organization_id, Membership.user_id == member_id,
    ))
    if not target:
        raise HTTPException(status_code=404, detail="Membre introuvable")
    if target.role == "owner" or (role == "admin" and actor_membership.role != "owner"):
        audit(
            db, request, "authorization.organization.denied", "failure",
            actor_id=user.id, organization_id=organization_id, resource_id=member_id,
        )
        db.commit()
        raise HTTPException(status_code=403, detail="Modification de rôle non autorisée")
    previous_role = target.role
    target.role = role
    audit(
        db, request, "organization.member.role_changed", "success",
        user.id, organization_id, member_id,
        target_type="user", target_id=member_id,
        actor_organization_id=organization_id,
        context={"old_role": previous_role, "new_role": role},
    )
    db.commit()
    return {"status": "ok"}


@app.delete("/organizations/{organization_id}/members/{member_id}")
def remove_member(organization_id: str, member_id: str, request: Request, user: CurrentUser, db: Db):
    actor_membership = require_membership(db, organization_id, user, request)
    require_manager(actor_membership, db, request, user)
    target = db.scalar(select(Membership).where(
        Membership.organization_id == organization_id, Membership.user_id == member_id,
    ))
    if not target:
        raise HTTPException(status_code=404, detail="Membre introuvable")
    if target.role == "owner" or (target.role == "admin" and actor_membership.role != "owner"):
        audit(
            db, request, "authorization.organization.denied", "failure",
            actor_id=user.id, organization_id=organization_id, resource_id=member_id,
        )
        db.commit()
        raise HTTPException(status_code=403, detail="Suppression de membre non autorisée")
    db.query(DocumentShare).filter(
        DocumentShare.user_id == member_id,
        DocumentShare.document_id.in_(
            select(Document.id).where(Document.organization_id == organization_id)
        ),
    ).delete(synchronize_session=False)
    removed_role = target.role
    db.delete(target)
    audit(
        db, request, "organization.member.removed", "success",
        user.id, organization_id, member_id,
        target_type="user", target_id=member_id,
        actor_organization_id=organization_id,
        context={"removed_role": removed_role},
    )
    db.commit()
    return {"status": "ok"}


@app.get("/organizations/{organization_id}/documents")
def list_documents(organization_id: str, request: Request, user: CurrentUser, db: Db, q: str = ""):
    require_membership(db, organization_id, user, request)
    documents = db.scalars(
        select(Document).where(Document.organization_id == organization_id)
        .order_by(desc(Document.updated_at))
    ).all()
    needle = q.strip().casefold()
    visible = [
        document for document in documents
        if doc_access(db, document, user) and (
            not needle or needle in document.title.casefold()
            or needle in document.description.casefold()
            or needle in document.original_name.casefold()
        )
    ]
    return {"documents": [document_view(db, document, user) for document in visible]}


@app.post("/organizations/{organization_id}/documents", status_code=201)
async def upload_document(
    organization_id: str, request: Request, user: CurrentUser, db: Db,
    title: str = Form(""), description: str = Form(""), file: UploadFile = File(...),
):
    require_membership(db, organization_id, user, request)
    title = title.strip() or Path(file.filename or "document").stem[:200]
    if len(title) > 200 or len(description) > 4000:
        raise HTTPException(status_code=422, detail="Métadonnées trop longues")
    suffix = Path(file.filename or "").suffix.lower()
    expected = ALLOWED_TYPES.get(suffix)
    if not expected:
        raise HTTPException(status_code=415, detail="Format accepté : PDF, TXT, PNG ou JPEG")
    content = await file.read(MAX_UPLOAD_SIZE + 1)
    if not content:
        raise HTTPException(status_code=400, detail="Le fichier est vide")
    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="Taille maximale : 15 Mo")
    expected_type, signature = expected
    if signature and not content.startswith(signature):
        raise HTTPException(status_code=415, detail="Le contenu du fichier ne correspond pas à son extension")
    if suffix == ".txt":
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=415, detail="Le fichier texte doit être encodé en UTF-8")
    storage_key = f"{uuid.uuid4()}{suffix}"
    target = FILE_ROOT / storage_key
    target.write_bytes(content)
    document = Document(
        id=str(uuid.uuid4()), organization_id=organization_id, owner_id=user.id,
        title=title, description=description.strip(),
        original_name=Path(file.filename or "document").name[:255], storage_key=storage_key,
        content_type=expected_type, size=len(content),
    )
    db.add(document)
    audit(db, request, "document.create", "success", user.id, organization_id, document.id)
    db.commit()
    return document_view(db, document, user)


@app.get("/documents/{document_id}")
def get_document(document_id: str, request: Request, user: CurrentUser, db: Db):
    document = require_document(db, document_id, user, request)
    audit(db, request, "document.view", "success", user.id, document.organization_id, document.id)
    db.commit()
    return document_view(db, document, user)


@app.patch("/documents/{document_id}")
def update_document(document_id: str, body: DocumentInput, request: Request, user: CurrentUser, db: Db):
    document = require_document(db, document_id, user, request, write=True)
    document.title = body.title.strip()
    document.description = body.description.strip()
    document.updated_at = utcnow()
    audit(db, request, "document.update", "success", user.id, document.organization_id, document.id)
    db.commit()
    return document_view(db, document, user)


@app.get("/documents/{document_id}/download")
def download_document(document_id: str, request: Request, user: CurrentUser, db: Db):
    document = require_document(db, document_id, user, request)
    path = (FILE_ROOT / document.storage_key).resolve()
    if path.parent != FILE_ROOT or not path.is_file():
        raise HTTPException(status_code=404, detail="Fichier introuvable")
    audit(db, request, "document.download", "success", user.id, document.organization_id, document.id)
    db.commit()
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", document.original_name) or "document"
    return FileResponse(
        path, media_type=document.content_type, filename=safe_name,
        headers={"Cache-Control": "private, no-store"},
    )


@app.delete("/documents/{document_id}")
def delete_document(document_id: str, request: Request, user: CurrentUser, db: Db):
    document = require_document(db, document_id, user, request)
    membership = require_membership(db, document.organization_id, user, request)
    if document.owner_id != user.id and membership.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Seul le propriétaire ou un administrateur peut supprimer ce document")
    path = FILE_ROOT / document.storage_key
    db.query(DocumentShare).filter(DocumentShare.document_id == document.id).delete()
    db.delete(document)
    audit(db, request, "document.delete", "success", user.id, document.organization_id, document.id)
    db.commit()
    path.unlink(missing_ok=True)
    return {"status": "ok"}


@app.get("/documents/{document_id}/shares")
def list_shares(document_id: str, request: Request, user: CurrentUser, db: Db):
    document = require_document(db, document_id, user, request)
    shares = db.execute(
        select(DocumentShare, User).join(User, User.id == DocumentShare.user_id)
        .where(DocumentShare.document_id == document.id)
    ).all()
    return {"shares": [
        {"user_id": share.user_id, "name": member.name, "email": member.email, "permission": share.permission}
        for share, member in shares
    ]}


@app.put("/documents/{document_id}/shares")
def set_share(document_id: str, body: ShareInput, request: Request, user: CurrentUser, db: Db):
    document = require_document(db, document_id, user, request, write=True)
    if body.permission not in ("read", "edit"):
        raise HTTPException(status_code=422, detail="Permission invalide")
    member = db.scalar(select(Membership).where(
        Membership.organization_id == document.organization_id,
        Membership.user_id == body.user_id,
    ))
    if not member or body.user_id == document.owner_id:
        raise HTTPException(status_code=404, detail="Membre introuvable")
    share = db.scalar(select(DocumentShare).where(
        DocumentShare.document_id == document.id, DocumentShare.user_id == body.user_id,
    ))
    if share:
        share.permission = body.permission
    else:
        share = DocumentShare(
            id=str(uuid.uuid4()), document_id=document.id, user_id=body.user_id,
            permission=body.permission,
        )
        db.add(share)
    audit(db, request, "document.share.update", "success", user.id, document.organization_id, document.id)
    db.commit()
    return {"status": "ok"}


@app.delete("/documents/{document_id}/shares/{member_id}")
def remove_share(document_id: str, member_id: str, request: Request, user: CurrentUser, db: Db):
    document = require_document(db, document_id, user, request, write=True)
    share = db.scalar(select(DocumentShare).where(
        DocumentShare.document_id == document.id, DocumentShare.user_id == member_id,
    ))
    if not share:
        raise HTTPException(status_code=404, detail="Partage introuvable")
    db.delete(share)
    audit(db, request, "document.share.remove", "success", user.id, document.organization_id, document.id)
    db.commit()
    return {"status": "ok"}


@app.get("/organizations/{organization_id}/activity")
def list_activity(organization_id: str, request: Request, user: CurrentUser, db: Db):
    membership = require_membership(db, organization_id, user, request)
    require_manager(membership, db, request, user)
    events = db.scalars(
        select(AuditEvent).where(AuditEvent.organization_id == organization_id)
        .order_by(desc(AuditEvent.created_at)).limit(100)
    ).all()
    return {"events": [
        {
            "id": event.id, "event_type": event.event_type, "actor_id": event.actor_id,
            "resource_id": event.resource_id, "result": event.result,
            "source_ip": event.source_ip, "request_id": event.request_id,
            "created_at": event.created_at.isoformat(),
        } for event in events
    ]}
