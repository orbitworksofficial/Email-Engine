import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

try:
    import resend
    HAS_RESEND = True
except ImportError:
    resend = None
    HAS_RESEND = False

from ai_email_engine.config import settings
from ai_email_engine.security.pii_crypto import mask_email
from ai_email_engine.services.alerting import alert_critical
from ai_email_engine.security.rls_middleware import get_request_id
from ai_email_engine.security.unsubscribe_tokens import generate_unsubscribe_token

logger = logging.getLogger("ai_email_engine.services.resend_dispatcher")




def append_unsubscribe_footer(body_html: str, recipient_email: str, tenant_id: str) -> str:
    """Appends RFC 8058 compliant opt-out link to outgoing HTML email body."""
    token = generate_unsubscribe_token(tenant_id, recipient_email)
    unsub_url = f"{settings.UNSUBSCRIBE_BASE_URL}?token={token}"
    footer = (
        f'<div style="margin-top:30px;border-top:1px solid #e5e7eb;font-size:12px;'
        f'color:#6b7280;text-align:center;padding-top:8px;">'
        f'<p>If you no longer wish to receive these emails, '
        f'<a href="{unsub_url}" style="color:#6b7280;text-decoration:underline;">unsubscribe here</a>.</p>'
        f"</div>"
    )
    if "</body>" in body_html:
        return body_html.replace("</body>", f"{footer}</body>")
    return body_html + footer


async def send_transactional_email(
    tenant_id: str,
    recipient_email: str,
    subject: str,
    body_html: str,
    sender_email: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Dispatches HTML email via Resend API with RFC 8058 List-Unsubscribe headers.
    Emits CRITICAL alert if send fails so operators know emails are not being delivered.
    Returns dict with id, status, and mock flag.
    """
    request_id = get_request_id()
    from_email = sender_email or settings.DEFAULT_SENDER_EMAIL
    token = generate_unsubscribe_token(tenant_id, recipient_email)
    unsub_url = f"{settings.UNSUBSCRIBE_BASE_URL}?token={token}"
    compliant_html = append_unsubscribe_footer(body_html, recipient_email, tenant_id)

    headers = {
        "List-Unsubscribe": f"<{unsub_url}>",
        "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        "X-Request-ID": request_id,
    }

    if not settings.RESEND_API_KEY or not HAS_RESEND:
        if settings.ENVIRONMENT == "production":
            alert_critical(
                "resend_missing_configuration",
                "RESEND_API_KEY and resend package are required in production environment",
                tenant_id=tenant_id,
                request_id=request_id,
            )
            return {"id": None, "status": "failed", "error": "RESEND_API_KEY and resend package required in production", "mock": False}

        mock_id = f"resend_mock_{uuid.uuid4().hex[:12]}"
        logger.info(
            f"[{request_id}] [MOCK DISPATCH] to={mask_email(recipient_email)} "
            f"subject='{subject}' id={mock_id}"
        )
        return {"id": mock_id, "status": "sent", "mock": True}


    try:
        resend.api_key = settings.RESEND_API_KEY
        params = {
            "from": from_email,
            "to": [recipient_email],
            "subject": subject,
            "html": compliant_html,
            "headers": headers,
        }
        email_res = resend.Emails.send(params)
        message_id = (
            email_res.get("id")
            if isinstance(email_res, dict)
            else getattr(email_res, "id", str(uuid.uuid4()))
        )
        logger.info(
            f"[{request_id}] [RESEND] Sent to={mask_email(recipient_email)} id={message_id}"
        )
        return {"id": message_id, "status": "sent", "mock": False}

    except Exception as e:
        alert_critical(
            "resend_dispatch_failure",
            f"Resend failed to {mask_email(recipient_email)}: {e}",
            tenant_id=tenant_id,
            request_id=request_id,
        )
        return {"id": None, "status": "failed", "error": str(e), "mock": False}
