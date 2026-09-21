import uuid
import logging
from contextvars import ContextVar
from typing import Optional

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response
    HAS_STARLETTE = True
except ImportError:
    HAS_STARLETTE = False
    BaseHTTPMiddleware = object
    Request = None
    Response = None

from ai_email_engine.config import settings

logger = logging.getLogger("ai_email_engine.security.rls_middleware")

# Per-request context variables — safe across async boundaries
_current_tenant_id: ContextVar[str] = ContextVar("current_tenant_id", default=settings.DEFAULT_TENANT_ID)
_current_request_id: ContextVar[str] = ContextVar("current_request_id", default="none")


def get_current_tenant_id() -> str:
    return _current_tenant_id.get()


def set_current_tenant_id(tenant_id: str) -> None:
    _current_tenant_id.set(tenant_id)


def get_request_id() -> str:
    return _current_request_id.get()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Middleware that:
    1. Generates a unique request_id (UUID4) for every request — used in all downstream logs
       for full request traceability across async hops.
    2. Sets default tenant context fallback.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())
        _current_request_id.set(request_id)
        _current_tenant_id.set(settings.DEFAULT_TENANT_ID)

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# Alias for backwards compatibility
TenantIsolationMiddleware = RequestIDMiddleware

