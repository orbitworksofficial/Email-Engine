import logging
from typing import Optional, Any
from datetime import datetime, timezone

logger = logging.getLogger("ai_email_engine.services.alerting")


def alert_critical(
    event: str,
    detail: str,
    tenant_id: Optional[str] = None,
    request_id: Optional[str] = None,
    extra: Optional[Any] = None
) -> None:
    """
    Emits a structured CRITICAL log entry for incidents that require operational attention.

    What this IS: a structured, request-ID-correlated log line at CRITICAL level — greppable,
    parseable, and far more useful than a plain logger.error() call.

    What this IS NOT: an alerting system. It does not page anyone. It does not send Slack
    messages, PagerDuty events, or emails. To get on-call paging you must attach an external
    log drain (Sentry, Datadog, CloudWatch Alarms, etc.) that watches for CRITICAL-level
    lines and fires your chosen notification channel.

    Events that call this:
    - Resend dispatch failure (emails going nowhere)
    - DB write failure during sequence processing
    - LLM fully exhausted (both providers down, fallback used)
    - Startup config validation failure (placeholder secrets in production)
    - Dead-letter webhook (exhausted all retries)
    """
    structured = {
        "level": "CRITICAL",
        "event": event,
        "detail": detail,
        "tenant_id": tenant_id[:8] + "..." if tenant_id else "unknown",
        "request_id": request_id or "none",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        structured["extra"] = str(extra)

    logger.critical(
        f"[ALERT] event={event} tenant={structured['tenant_id']} "
        f"request_id={structured['request_id']} | {detail}",
        extra=structured
    )


def alert_warning(
    event: str,
    detail: str,
    tenant_id: Optional[str] = None,
    request_id: Optional[str] = None,
) -> None:
    """Emits a structured WARNING log for degraded-but-not-broken conditions."""
    logger.warning(
        f"[ALERT:WARNING] event={event} tenant={tenant_id[:8] + '...' if tenant_id else 'unknown'} "
        f"request_id={request_id or 'none'} | {detail}"
    )
