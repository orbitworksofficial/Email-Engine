import logging
import httpx
from typing import Dict, Any, Optional

from ai_email_engine.config import settings
from ai_email_engine.security.rls_middleware import get_request_id

logger = logging.getLogger("ai_email_engine.services.crm_sync")


async def notify_crm_event(
    event_type: str,
    lead_id: str,
    email: str,
    tenant_id: str,
    details: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Asynchronously notifies Kashif's Custom CRM about email engine events.
    Events: 'email_sent', 'meeting_booked', 'opted_out', 'bounced', 'replied'
    """
    crm_url = settings.CRM_CALLBACK_URL
    if not crm_url:
        logger.debug(f"[{get_request_id()}] CRM_CALLBACK_URL not set. Skipping CRM event dispatch ({event_type})")
        return False

    payload = {
        "event_type": event_type,
        "lead_id": lead_id,
        "email": email,
        "tenant_id": tenant_id,
        "details": details or {},
    }

    headers = {
        "Content-Type": "application/json",
        "X-Engine-Secret": settings.CRM_WEBHOOK_SECRET,
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(crm_url, json=payload, headers=headers)
            if resp.status_code in (200, 201, 202):
                logger.info(f"[{get_request_id()}] Successfully notified CRM of '{event_type}' for lead {lead_id}")
                return True
            else:
                logger.warning(f"[{get_request_id()}] CRM callback returned non-2xx ({resp.status_code}): {resp.text}")
                return False
    except Exception as e:
        logger.warning(f"[{get_request_id()}] Failed to dispatch CRM notification: {e}")
        return False
