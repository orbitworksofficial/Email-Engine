import base64
import hashlib
import hmac
import logging
import time
from typing import Optional, Tuple
from fastapi import APIRouter, Query, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from ai_email_engine.config import settings
from ai_email_engine.database.connection import get_db_client
from ai_email_engine.security.pii_crypto import hash_pii_for_lookup
from ai_email_engine.security.unsubscribe_tokens import generate_unsubscribe_token, verify_unsubscribe_token
from ai_email_engine.services.alerting import alert_warning

logger = logging.getLogger("ai_email_engine.api.compliance")
router = APIRouter(prefix="/api/v1", tags=["Compliance"])


def _record_unsubscribe(tenant_id: str, email_hash: str) -> None:
    db = get_db_client()
    try:
        db.table("suppression_list").insert({
            "tenant_id": tenant_id,
            "email": email_hash,
            "reason": "unsubscribe_link",
        }).execute()
        logger.info(f"[UNSUBSCRIBE] Email hash {email_hash[:8]} suppressed for tenant {tenant_id[:8]}")
    except Exception as e:
        err_str = str(e).lower()
        if "unique" in err_str or "duplicate" in err_str:
            pass
        else:
            alert_warning("unsubscribe_insert_failure", f"Failed to record unsubscribe: {e}", tenant_id=tenant_id)

    # Update active campaigns using indexed tenant_id + email_hash query
    try:
        res = db.table("email_campaign_states").select("id").eq("tenant_id", tenant_id).eq("email_hash", email_hash).execute()
        for row in (res.data or []):
            db.table("email_campaign_states").update({
                "status": "paused_unsubscribed",
                "next_scheduled_at": None,
            }).eq("id", row["id"]).execute()
    except Exception as e:
        logger.warning(f"[UNSUBSCRIBE] Campaign pause failure: {e}")


@router.get("/unsubscribe", response_class=HTMLResponse)
async def handle_unsubscribe_get(
    token: Optional[str] = Query(None, description="Signed unsubscribe token"),
    email: Optional[str] = Query(None, description="Email address (legacy dev mode)"),
    tenant_id: Optional[str] = Query(None, description="Tenant identifier (legacy dev mode)"),
):
    """
    GET /unsubscribe — Anti-prefetch GET page.
    Displays a confirmation button so link scanners (Outlook Safe Links, Gmail proxies)
    do NOT trigger automated unsubscribes on link prefetch.
    """
    verified = None
    if token:
        verified = verify_unsubscribe_token(token)
    elif email and tenant_id and settings.ALLOW_UNSIGNED_WEBHOOKS and settings.ENVIRONMENT != "production":
        # Dev testing fallback gated strictly on ALLOW_UNSIGNED_WEBHOOKS
        verified = (tenant_id, hash_pii_for_lookup(email))
        token = generate_unsubscribe_token(tenant_id, email)

    if not verified:
        return HTMLResponse(content="""
<!DOCTYPE html>
<html lang="en">
<head><title>Invalid Unsubscribe Link — OrbitWorks</title></head>
<body style="font-family:sans-serif;text-align:center;padding:50px;">
  <h2>Invalid or Expired Unsubscribe Link</h2>
  <p>This unsubscribe link is invalid or has expired. Please contact support if you need assistance.</p>
</body>
</html>
""", status_code=400)

    # Render confirmation form (POSTs to /unsubscribe)
    return HTMLResponse(content=f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Confirm Unsubscribe — OrbitWorks</title>
  <style>
    body {{ font-family: Arial, sans-serif; display: flex; justify-content: center;
           align-items: center; min-height: 100vh; margin: 0; background: #f9fafb; }}
    .card {{ background: white; border-radius: 12px; padding: 48px 40px; text-align: center;
            box-shadow: 0 4px 24px rgba(0,0,0,0.07); max-width: 440px; }}
    h1 {{ color: #111827; font-size: 24px; margin-bottom: 12px; }}
    p  {{ color: #6b7280; font-size: 15px; line-height: 1.6; margin-bottom: 24px; }}
    button {{ background: #dc2626; color: white; border: none; padding: 12px 24px;
              font-size: 16px; border-radius: 6px; cursor: pointer; font-weight: 600; }}
    button:hover {{ background: #b91c1c; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Unsubscribe Confirmation</h1>
    <p>Click below to confirm that you wish to unsubscribe from future emails.</p>
    <form action="/api/v1/unsubscribe" method="POST">
      <input type="hidden" name="token" value="{token}" />
      <button type="submit">Unsubscribe Me</button>
    </form>
  </div>
</body>
</html>
""", status_code=200)


@router.post("/unsubscribe")
async def handle_unsubscribe_post(
    request: Request,
    token: Optional[str] = Query(None),
):
    """
    POST /unsubscribe — Process unsubscribe.
    Supports form submission (browser confirm) and RFC 8058 One-Click header POST.
    """
    body = await request.body()
    body_str = body.decode("utf-8") if body else ""
    token_from_body = None
    if "token=" in body_str:
        import urllib.parse
        parsed = urllib.parse.parse_qs(body_str)
        token_from_body = parsed.get("token", [None])[0]

    final_token = token or token_from_body or request.query_params.get("token")
    verified = verify_unsubscribe_token(final_token) if final_token else None

    # Dev testing fallback gated strictly on ALLOW_UNSIGNED_WEBHOOKS
    if not verified and settings.ALLOW_UNSIGNED_WEBHOOKS and settings.ENVIRONMENT != "production":
        req_email = request.query_params.get("email")
        req_tenant = request.query_params.get("tenant_id")
        if req_email and req_tenant:
            verified = (req_tenant, hash_pii_for_lookup(req_email))


    if not verified:
        raise HTTPException(status_code=400, detail="Invalid or expired unsubscribe token")

    tenant_id, email_hash = verified
    _record_unsubscribe(tenant_id, email_hash)

    # Return JSON for RFC 8058 automated callers, HTML for browser form POSTs
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type or "List-Unsubscribe" in request.headers.get("List-Unsubscribe-Post", ""):
        return JSONResponse(content={"status": "success", "message": "Unsubscribed successfully"})

    return HTMLResponse(content="""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Unsubscribed — OrbitWorks</title>
  <style>
    body { font-family: Arial, sans-serif; display: flex; justify-content: center;
           align-items: center; min-height: 100vh; margin: 0; background: #f9fafb; }
    .card { background: white; border-radius: 12px; padding: 48px 40px; text-align: center;
            box-shadow: 0 4px 24px rgba(0,0,0,0.07); max-width: 440px; }
    h1 { color: #111827; font-size: 24px; margin-bottom: 12px; }
    p  { color: #6b7280; font-size: 15px; line-height: 1.6; }
  </style>
</head>
<body>
  <div class="card">
    <h1>You've been unsubscribed</h1>
    <p>You will no longer receive emails from OrbitWorks on this address.</p>
  </div>
</body>
</html>
""", status_code=200)

