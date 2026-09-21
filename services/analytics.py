import logging
from typing import Dict, Any, Optional

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

from ai_email_engine.config import settings
from ai_email_engine.services.alerting import alert_warning

from ai_email_engine.security.pii_crypto import mask_email, hash_pii_for_lookup

logger = logging.getLogger("ai_email_engine.services.analytics")

GA4_COLLECT_ENDPOINT = "https://www.google-analytics.com/mp/collect"
GA4_DEBUG_ENDPOINT = "https://www.google-analytics.com/debug/mp/collect"


async def track_ga4_event(
    tenant_id: str,
    event_name: str,
    params: Dict[str, Any],
    client_id: Optional[str] = None,
) -> bool:
    """
    Fires a server-to-server conversion event via GA4 Measurement Protocol.
    In non-production environments, uses the GA4 debug endpoint to validate schema.
    PII parameters (invitee_email, email) are sanitized/hashed to avoid GA4 terms violations.
    """
    safe_params = dict(params)
    if "invitee_email" in safe_params:
        safe_params["invitee_email"] = hash_pii_for_lookup(safe_params["invitee_email"])
    if "email" in safe_params and "@" in str(safe_params["email"]):
        safe_params["email"] = mask_email(safe_params["email"])

    if not HAS_HTTPX or not settings.GA4_MEASUREMENT_ID or not settings.GA4_API_SECRET:
        logger.info(
            f"[GA4 MOCK] event={event_name} tenant={tenant_id[:8]} params={safe_params}"
        )
        return True

    endpoint = (
        GA4_DEBUG_ENDPOINT
        if settings.ENVIRONMENT != "production"
        else GA4_COLLECT_ENDPOINT
    )
    url = f"{endpoint}?measurement_id={settings.GA4_MEASUREMENT_ID}&api_secret={settings.GA4_API_SECRET}"

    payload = {
        "client_id": client_id or f"server.{tenant_id[:8]}",
        "events": [{"name": event_name, "params": {**safe_params, "tenant_id": tenant_id}}],
    }


    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            res = await client.post(url, json=payload)

            # Issue 16 — parse GA4 debug validation response in non-prod
            if settings.ENVIRONMENT != "production":
                try:
                    body = res.json()
                    messages = body.get("validationMessages", [])
                    if messages:
                        alert_warning(
                            "ga4_validation_failure",
                            f"GA4 event '{event_name}' has validation errors: {messages}",
                            tenant_id=tenant_id,
                        )
                    else:
                        logger.debug(f"[GA4 DEBUG] Event '{event_name}' passed GA4 schema validation")
                except Exception:
                    pass  # Debug endpoint response parse failure is non-critical

            if res.status_code in (200, 204):
                logger.info(f"[GA4] Fired '{event_name}' for tenant={tenant_id[:8]}")
                return True
            else:
                alert_warning(
                    "ga4_http_error",
                    f"GA4 returned status {res.status_code} for event '{event_name}'",
                    tenant_id=tenant_id,
                )
    except Exception as e:
        alert_warning("ga4_dispatch_error", f"GA4 event '{event_name}' dispatch error: {e}", tenant_id=tenant_id)

    return False
