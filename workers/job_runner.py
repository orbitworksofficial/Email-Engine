import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from ai_email_engine.database.connection import get_db_client, set_tenant_session_context
from ai_email_engine.services.sequence_engine import (
    process_new_lead_sequence,
    handle_calendly_booking_event,
    handle_resend_webhook_event,
)
from ai_email_engine.services.alerting import alert_critical, alert_warning
from ai_email_engine.security.rls_middleware import get_request_id

logger = logging.getLogger("ai_email_engine.workers.job_runner")

MAX_RETRIES = 5
RETRY_BACKOFF_SECONDS = [10, 30, 90, 300, 900]  # exponential: 10s, 30s, 1.5m, 5m, 15m


_background_tasks = set()


def _schedule_background_task(coro):
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


def _update_webhook_event_status(
    tenant_id: str,
    payload_hash: Optional[str],
    status: str,
    error_msg: Optional[str] = None,
    retry_count: int = 0,
) -> None:
    """Updates webhook_events row status for durable crash recovery tracking."""
    if not payload_hash:
        return
    db = get_db_client()
    set_tenant_session_context(db, tenant_id)
    update = {
        "status": status,
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        db.table("webhook_events").update(update).eq("tenant_id", tenant_id).eq("payload_hash", payload_hash).execute()
    except Exception as e:
        logger.warning(f"Failed to update webhook_events status: {e}")



async def _execute_job(tenant_id: str, provider: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Routes a webhook payload to the appropriate service handler and returns status result."""
    set_tenant_session_context(get_db_client(), tenant_id)
    from ai_email_engine.api.webhooks import extract_provider_lead_payload
    normalized_payload = extract_provider_lead_payload(provider, payload)
    if provider in ("meta_ads", "linkedin_ads", "google_ads", "website"):
        return await process_new_lead_sequence(tenant_id, provider, normalized_payload)
    elif provider == "calendly":
        return await handle_calendly_booking_event(tenant_id, normalized_payload)
    elif provider == "resend":
        return await handle_resend_webhook_event(tenant_id, normalized_payload)
    else:
        logger.warning(f"Unknown provider '{provider}' in job_runner — skipping")
        return {"status": "skipped"}



async def run_job_with_retry(
    tenant_id: str,
    provider: str,
    payload: Dict[str, Any],
    payload_hash: Optional[str] = None,
) -> None:
    """
    Executes a webhook job with exponential backoff retry (up to MAX_RETRIES).
    On final failure, marks webhook_events as 'dead_letter' and fires CRITICAL alert.

    This replaces FastAPI BackgroundTasks as the durable execution mechanism (Issue 3 fix).
    """
    set_tenant_session_context(get_db_client(), tenant_id)
    _update_webhook_event_status(tenant_id, payload_hash, "processing")

    for attempt in range(MAX_RETRIES + 1):
        try:
            res = await _execute_job(tenant_id, provider, payload)
            status_val = res.get("status") if isinstance(res, dict) else "completed"
            retryable = res.get("retryable", True) if isinstance(res, dict) else True

            if status_val in ("permanent_error", "invalid") or not retryable:
                err_msg = res.get("message", "Permanent input error") if isinstance(res, dict) else "Permanent input error"
                logger.warning(
                    f"[JOB RUNNER] Permanent non-retryable error for {provider} tenant={tenant_id[:8]}: {err_msg}"
                )
                alert_critical(
                    "webhook_job_permanent_failure",
                    f"Job dead-lettered (permanent failure) for provider={provider}: {err_msg}",
                    tenant_id=tenant_id,
                )
                _update_webhook_event_status(tenant_id, payload_hash, "dead_letter", err_msg)
                return

            if status_val in ("error", "failed"):
                raise RuntimeError(f"Service execution error: {res.get('message', 'Unknown error')}")

            final_event_status = "pending_enrichment" if status_val == "pending_enrichment" else "completed"
            _update_webhook_event_status(tenant_id, payload_hash, final_event_status)
            logger.info(f"[JOB RUNNER] Completed ({final_event_status}): provider={provider} tenant={tenant_id[:8]} attempt={attempt + 1}")
            return
        except Exception as e:
            if attempt < MAX_RETRIES:
                backoff = RETRY_BACKOFF_SECONDS[min(attempt, len(RETRY_BACKOFF_SECONDS) - 1)]
                logger.warning(
                    f"[JOB RUNNER] Attempt {attempt + 1}/{MAX_RETRIES + 1} failed for {provider} "
                    f"tenant={tenant_id[:8]}: {e}. Retrying in {backoff}s"
                )
                await asyncio.sleep(backoff)
            else:
                alert_critical(
                    "webhook_job_dead_letter",
                    f"Job exhausted {MAX_RETRIES} retries for provider={provider}: {e}",
                    tenant_id=tenant_id,
                )
                _update_webhook_event_status(tenant_id, payload_hash, "dead_letter", str(e))


async def recover_unprocessed_webhooks() -> None:
    """
    On startup, sweeps any webhook_events rows stuck in 'received' or 'processing'
    (left behind by a prior crash) and replays them through run_job_with_retry.
    This is the crash-recovery half of the durable queue pattern (Issue 3).
    """
    db = get_db_client()
    try:
        res = db.table("webhook_events").select("*").eq("status", "received").execute()
        stranded = res.data if res and res.data else []

        # Also recover 'processing' rows that never completed
        res2 = db.table("webhook_events").select("*").eq("status", "processing").execute()
        stranded += res2.data if res2 and res2.data else []

        if stranded:
            logger.info(f"[RECOVERY] Found {len(stranded)} stranded webhook event(s) — replaying")
            for event in stranded:
                _schedule_background_task(run_job_with_retry(
                    tenant_id=event["tenant_id"],
                    provider=event["provider"],
                    payload=event.get("raw_payload", {}),
                    payload_hash=event.get("payload_hash"),
                ))

        else:
            logger.info("[RECOVERY] No stranded webhook events found")
    except Exception as e:
        alert_warning("recovery_sweep_failure", f"Startup recovery sweep failed: {e}")
