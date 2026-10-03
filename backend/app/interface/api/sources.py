"""Source toggle API — analyst-accessible dedicated routes.

GET  /api/settings/sources       → effective toggles (DB→env fallback)
PUT  /api/settings/sources       → update toggles (partial update)
GET  /api/settings/sources/config → configuration status for wizard (with non-secret fields)
PUT  /api/settings/sources/config → set method + persist credentials (partial update supported)

Auth is handled by apply_role_guard via ROUTER_POLICIES in main.py:
read=analyst, write=analyst. No inline dependencies needed here.
"""
import logging
import re
import secrets as crypto_secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ...db import get_db, get_tenant_id
from ...application.system_config import _init_defaults, update_settings, get_config_value
from ...application.source_control import is_source_enabled
from ...models import SystemConfig

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/settings", tags=["sources"])

VALID_SOURCES = {"wazuh", "suricata"}
VALID_METHODS = {
    "wazuh": {"webhook", "api_indexer"},
    "suricata": {"webhook", "ssh"},
}

# Which non-secret keys to expose in fields for each method
WAZUH_API_INDEXER_FIELDS = {"url", "user", "indexer_url", "indexer_user"}
SURICATA_SSH_FIELDS = {"host", "port", "user"}

# ── Webhook slugs (suffix secret de l'URL par tenant) ─────────────────
WEBHOOK_SLUG_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
WEBHOOK_SLUG_LEN = 16
WEBHOOK_SLUG_REGEX = re.compile(r"^[A-Za-z0-9]{6,64}$")


class SourcesUpdate(BaseModel):
    host_agent: Optional[bool] = None
    wazuh: Optional[bool] = None
    suricata: Optional[bool] = None


class SourcesConfigUpdate(BaseModel):
    source: str
    method: str
    data: dict = {}


def _effective_value(db, section, key, tenant_id):
    """Get the effective (DB or default) string value for a config key."""
    return get_config_value(db, section, key, tenant_id=tenant_id)


def _is_nonempty(val: str) -> bool:
    return bool(val and val.strip())


def _password_is_set(db, section, tenant_id):
    """Check if the password field for a given section is non-empty."""
    val = get_config_value(db, section, "password", tenant_id=tenant_id)
    return _is_nonempty(val)


def _token_is_set(db, section, tenant_id):
    """Check if the webhook token for a given section is non-empty."""
    val = get_config_value(db, section, "token", tenant_id=tenant_id)
    return _is_nonempty(val)


# ── Webhook slugs ─────────────────────────────────────────────────────

def _all_webhook_slugs(db, section, exclude_tenant_id=None):
    """Ensemble des slugs persistés d'une section webhook (tous tenants)."""
    q = db.query(SystemConfig).filter(
        SystemConfig.section == section,
        SystemConfig.key == "slug",
    )
    if exclude_tenant_id is not None:
        q = q.filter(SystemConfig.tenant_id != exclude_tenant_id)
    return {row.value for row in q.all() if row.value}


def _fresh_webhook_slug(db, section):
    """Génère un slug base62 aléatoire, garanti unique (hors collision)."""
    for _ in range(10):
        slug = "".join(crypto_secrets.choice(WEBHOOK_SLUG_ALPHABET) for _ in range(WEBHOOK_SLUG_LEN))
        if slug not in _all_webhook_slugs(db, section):
            return slug
    raise RuntimeError(f"Impossible de générer un slug unique pour {section}")


def _ensure_webhook_slug(db, source, tenant_id):
    """Retourne le slug existant ; sinon le génère et le persiste (lazy-gen)."""
    section = f"{source}_webhook"
    existing = get_config_value(db, section, "slug", tenant_id=tenant_id)
    if existing:
        return existing
    slug = _fresh_webhook_slug(db, section)
    update_settings(db, section, {"slug": slug}, tenant_id=tenant_id)
    return slug


def _webhook_url(base_url, source, slug):
    base = (str(base_url) or "").rstrip("/")
    return f"{base}/api/{source}/webhook/{slug}"


def _compute_config(db, tenant_id, base_url=None):
    """Compute the config response for both sources, including non-secret fields."""
    result = {}

    # ── WAZUH ──
    wazuh_method = _effective_value(db, "sources", "wazuh_method", tenant_id)

    if wazuh_method == "api_indexer":
        # Non-secret field values for the frontend
        url = _effective_value(db, "wazuh_api", "url", tenant_id)
        user = _effective_value(db, "wazuh_api", "user", tenant_id)
        idx_url = _effective_value(db, "wazuh_indexer", "url", tenant_id)
        idx_user = _effective_value(db, "wazuh_indexer", "user", tenant_id)
        fields = {}
        if _is_nonempty(url):
            fields["url"] = url
        if _is_nonempty(user):
            fields["user"] = user
        if _is_nonempty(idx_url):
            fields["indexer_url"] = idx_url
        if _is_nonempty(idx_user):
            fields["indexer_user"] = idx_user
        # Two distinct password_set indicators (CHOSEN: more correct than single bool)
        fields["password_set"] = _password_is_set(db, "wazuh_api", tenant_id)
        fields["indexer_password_set"] = _password_is_set(db, "wazuh_indexer", tenant_id)

        # missing keys from contract frontend
        missing = []
        if not _is_nonempty(url):
            missing.append("url")
        if not _is_nonempty(user):
            missing.append("user")
        if not fields["password_set"]:
            missing.append("password")
        if not _is_nonempty(idx_url):
            missing.append("indexer_url")
        if not _is_nonempty(idx_user):
            missing.append("indexer_user")
        if not fields["indexer_password_set"]:
            missing.append("indexer_password")
        configured = len(missing) == 0

    elif wazuh_method == "webhook":
        configured = True
        missing = []
        slug = _ensure_webhook_slug(db, "wazuh", tenant_id)
        fields = {
            "token_set": _token_is_set(db, "wazuh_webhook", tenant_id),
            "slug": slug,
            "url": _webhook_url(base_url, "wazuh", slug),
        }

    else:
        configured = False
        missing = []
        fields = {}

    result["wazuh"] = {
        "configured": configured,
        "method": wazuh_method if wazuh_method in VALID_METHODS["wazuh"] else None,
        "missing": missing,
        "fields": fields,
    }

    # ── SURICATA ──
    suricata_method = _effective_value(db, "sources", "suricata_method", tenant_id)

    if suricata_method == "ssh":
        host = _effective_value(db, "suricata_ssh", "host", tenant_id)
        port = _effective_value(db, "suricata_ssh", "port", tenant_id)
        user = _effective_value(db, "suricata_ssh", "user", tenant_id)
        fields = {}
        if _is_nonempty(host):
            fields["host"] = host
        if _is_nonempty(port):
            fields["port"] = str(port)
        if _is_nonempty(user):
            fields["user"] = user
        fields["password_set"] = _password_is_set(db, "suricata_ssh", tenant_id)

        missing = []
        if not _is_nonempty(host):
            missing.append("host")
        if not _is_nonempty(port):
            missing.append("port")
        if not _is_nonempty(user):
            missing.append("user")
        if not fields["password_set"]:
            missing.append("password")
        configured = len(missing) == 0

    elif suricata_method == "webhook":
        configured = True
        missing = []
        slug = _ensure_webhook_slug(db, "suricata", tenant_id)
        fields = {
            "token_set": _token_is_set(db, "suricata_webhook", tenant_id),
            "slug": slug,
            "url": _webhook_url(base_url, "suricata", slug),
        }

    else:
        configured = False
        missing = []
        fields = {}

    result["suricata"] = {
        "configured": configured,
        "method": suricata_method if suricata_method in VALID_METHODS["suricata"] else None,
        "missing": missing,
        "fields": fields,
    }

    return result


@router.get("/sources")
def get_sources(request: Request, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    _init_defaults(db, tenant_id=tenant_id)
    return {
        "host_agent": is_source_enabled(db, "host_agent", tenant_id),
        "wazuh": is_source_enabled(db, "wazuh", tenant_id),
        "suricata": is_source_enabled(db, "suricata", tenant_id),
    }


@router.put("/sources")
def put_sources(request: Request, body: SourcesUpdate, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    _init_defaults(db, tenant_id=tenant_id)

    data = body.model_dump(exclude_unset=True)
    if not data:
        raise HTTPException(status_code=400, detail="No valid fields provided")

    update_settings(db, "sources", data, tenant_id=tenant_id)

    return {
        "status": "ok",
        "sources": {
            "host_agent": is_source_enabled(db, "host_agent", tenant_id),
            "wazuh": is_source_enabled(db, "wazuh", tenant_id),
            "suricata": is_source_enabled(db, "suricata", tenant_id),
        },
    }


@router.get("/sources/config")
def get_sources_config(request: Request, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    _init_defaults(db, tenant_id=tenant_id)
    return _compute_config(db, tenant_id, base_url=request.base_url)


@router.put("/sources/config")
def put_sources_config(request: Request, body: SourcesConfigUpdate, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    _init_defaults(db, tenant_id=tenant_id)

    source = body.source.strip()
    method = body.method.strip()

    if source not in VALID_SOURCES:
        raise HTTPException(status_code=400, detail=f"Invalid source: {source}")
    if method not in VALID_METHODS[source]:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid method '{method}' for source '{source}'",
        )

    # Persist method (always — even when just changing method)
    method_field = f"{source}_method"
    update_settings(db, "sources", {method_field: method}, tenant_id=tenant_id)

    # Persist credentials based on source/method — PARTIAL UPDATE: only write what's provided
    data = body.data
    if source == "wazuh" and method == "api_indexer":
        # Only write fields present in data (don't default to "")
        wazuh_updates = {}
        if "url" in data:
            wazuh_updates["url"] = data["url"]
        if "user" in data:
            wazuh_updates["user"] = data["user"]
        if "password" in data:
            wazuh_updates["password"] = data["password"]
        if wazuh_updates:
            update_settings(db, "wazuh_api", wazuh_updates, tenant_id=tenant_id)

        idx_updates = {}
        if "indexer_url" in data:
            idx_updates["url"] = data["indexer_url"]  # Maps to wazuh_indexer.url
        if "indexer_user" in data:
            idx_updates["user"] = data["indexer_user"]
        if "indexer_password" in data:
            idx_updates["password"] = data["indexer_password"]
        if idx_updates:
            update_settings(db, "wazuh_indexer", idx_updates, tenant_id=tenant_id)

        # Reload wazuh service config
        try:
            from ...services.wazuh_service import wazuh_service
            wazuh_service.reload_config(db)
        except Exception:
            pass

    elif source == "suricata" and method == "ssh":
        ssh_updates = {}
        if "host" in data:
            ssh_updates["host"] = data["host"]
        if "port" in data:
            ssh_updates["port"] = str(data["port"])
        if "user" in data:
            ssh_updates["user"] = data["user"]
        if "password" in data:
            ssh_updates["password"] = data["password"]
        if ssh_updates:
            update_settings(db, "suricata_ssh", ssh_updates, tenant_id=tenant_id)

    # Webhook token persistence (both wazuh and suricata use method "webhook")
    elif method == "webhook":
        webhook_section = f"{source}_webhook"
        if "slug" in data:
            slug_val = str(data["slug"] or "").strip()
            if slug_val == "":
                # Rotation forcée : on génère un nouveau slug aléatoire.
                new_slug = _fresh_webhook_slug(db, webhook_section)
                update_settings(db, webhook_section, {"slug": new_slug}, tenant_id=tenant_id)
            else:
                if not WEBHOOK_SLUG_REGEX.match(slug_val):
                    raise HTTPException(
                        status_code=400,
                        detail="slug must be 6-64 characters [A-Za-z0-9]",
                    )
                clash = db.query(SystemConfig).filter(
                    SystemConfig.section == webhook_section,
                    SystemConfig.key == "slug",
                    SystemConfig.value == slug_val,
                    SystemConfig.tenant_id != tenant_id,
                ).first()
                if clash is not None:
                    raise HTTPException(
                        status_code=409,
                        detail="slug already in use by another tenant",
                    )
                update_settings(db, webhook_section, {"slug": slug_val}, tenant_id=tenant_id)
        if "token" in data:
            token_val = data["token"].strip()
            if len(token_val) > 200:
                raise HTTPException(status_code=400, detail="Token exceeds 200 characters")
            if token_val == "":
                # Empty token → clear directly (bypass update_settings is_secret guard)
                row = db.query(SystemConfig).filter_by(
                    section=webhook_section, key="token", tenant_id=tenant_id
                ).first()
                if row:
                    row.value = ""
                    db.commit()
            else:
                update_settings(db, webhook_section, {"token": token_val}, tenant_id=tenant_id)

    # Recompute effective config
    config = _compute_config(db, tenant_id, base_url=request.base_url)

    return {"status": "ok", "config": config}


@router.post("/sources/{source}/rotate-url")
def rotate_webhook_url(source: str, request: Request, db: Session = Depends(get_db)):
    """Régénère le slug webhook (révoque l'ancienne URL) pour le tenant."""
    tenant_id = get_tenant_id(request)
    _init_defaults(db, tenant_id=tenant_id)

    if source not in VALID_SOURCES:
        raise HTTPException(status_code=400, detail=f"Invalid source: {source}")

    webhook_section = f"{source}_webhook"
    new_slug = _fresh_webhook_slug(db, webhook_section)
    update_settings(db, webhook_section, {"slug": new_slug}, tenant_id=tenant_id)

    config = _compute_config(db, tenant_id, base_url=request.base_url)
    return {"status": "ok", "config": config}
