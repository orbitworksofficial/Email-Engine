import hashlib
import logging
from typing import Optional, Tuple
from contextvars import ContextVar

from fastapi import Security, HTTPException, Header
from fastapi.security import APIKeyHeader

from ai_email_engine.database.connection import get_db_client, set_tenant_session_context

logger = logging.getLogger("ai_email_engine.security.api_key_auth")

# FastAPI security scheme — reads X-API-Key header
_api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)

# Per-request ContextVar holding the resolved tenant_id from the API key
_authenticated_tenant_id: ContextVar[Optional[str]] = ContextVar("authenticated_tenant_id", default=None)


def hash_api_key(raw_key: str) -> str:
    """SHA-256 hash of the raw API key. Keys are never stored in plaintext."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def resolve_tenant_from_api_key(raw_key: str) -> Optional[str]:
    """
    Looks up the tenant_id associated with this API key hash.
    Returns None if the key is not found or is inactive.
    """
    db = get_db_client()
    key_hash = hash_api_key(raw_key)
    try:
        res = (
            db.table("tenant_api_keys")
            .select("tenant_id")
            .eq("api_key_hash", key_hash)
            .eq("is_active", True)
            .execute()
        )
        if res and res.data:
            tenant_id = res.data[0]["tenant_id"]
            set_tenant_session_context(db, tenant_id)
            # Update last_used_at (best-effort, non-blocking)
            try:
                from datetime import datetime, timezone
                db.table("tenant_api_keys").update(
                    {"last_used_at": datetime.now(timezone.utc).isoformat()}
                ).eq("api_key_hash", key_hash).execute()
            except Exception:
                pass
            return tenant_id
    except Exception as e:
        logger.warning(f"API key lookup error: {e}")
    return None


async def require_api_key(x_api_key: Optional[str] = Security(_api_key_scheme)) -> str:
    """
    FastAPI dependency. Validates X-API-Key header and returns the authenticated tenant_id.
    Raises 401 if missing or invalid.
    Use: `tenant_id: str = Depends(require_api_key)`
    """
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    tenant_id = resolve_tenant_from_api_key(x_api_key)
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")

    _authenticated_tenant_id.set(tenant_id)
    return tenant_id


async def optional_api_key(x_api_key: Optional[str] = Security(_api_key_scheme)) -> Optional[str]:
    """
    Optional variant — returns tenant_id or None. Used on endpoints that work with
    or without authentication (e.g. dev/test mode).
    """
    if not x_api_key:
        return None
    tenant_id = resolve_tenant_from_api_key(x_api_key)
    if tenant_id:
        _authenticated_tenant_id.set(tenant_id)
    return tenant_id
