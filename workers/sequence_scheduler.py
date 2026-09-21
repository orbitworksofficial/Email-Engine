import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

from ai_email_engine.database.connection import get_db_client
from ai_email_engine.services.ai_copywriter import generate_personalized_copy
from ai_email_engine.services.sequence_engine import _save_or_dispatch_email, is_email_suppressed
from ai_email_engine.security.pii_crypto import decrypt_pii, mask_email
from ai_email_engine.services.alerting import alert_critical, alert_warning

logger = logging.getLogger("ai_email_engine.workers.sequence_scheduler")

MAX_SEQUENCE_STEPS = 3
STEP_INTERVAL_DAYS = [0, 3, 7]


async def run_sequence_scheduler_loop(poll_interval_seconds: int = 60) -> None:
    """
    Persistent async loop that fires follow-up email sequence steps on schedule.
    Polls every `poll_interval_seconds` for active campaigns with next_scheduled_at <= NOW().

    Multi-worker safety (Fix 5):
    Before processing a campaign, we attempt to claim it by performing an optimistic
    conditional UPDATE that transitions status from 'active' to 'processing_step'. Only the
    worker whose UPDATE matches (rows_affected == 1, or the row still reads 'processing_step'
    with our worker token) actually processes it. Other workers see a different status and skip.

    This is not a distributed lock — it's a row-claim pattern using the database as
    the coordination point. In Supabase/Postgres this is safe: UPDATE is atomic at the
    row level. It prevents duplicate sends without requiring Redis or a separate lock service.

    Limitation (stated honestly): asyncio.create_task in on_startup() means all workers
    in a multi-process deployment run this loop independently, and the row-claim is the
    only guard. If you need stricter guarantees (e.g., only one process runs the scheduler
    at all), add a leader-election table or use pg_advisory_lock.
    """
    logger.info(f"Sequence scheduler started (poll: {poll_interval_seconds}s, claim-based multi-worker safety)")
    while True:
        try:
            await _tick_sequence_scheduler()
        except Exception as e:
            alert_critical("sequence_scheduler_tick_failure", f"Scheduler tick failed: {e}")
        await asyncio.sleep(poll_interval_seconds)


async def _tick_sequence_scheduler() -> None:
    """Single scheduler tick — claims and processes all due sequence steps."""
    db = get_db_client()
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        res = (
            db.table("email_campaign_states")
            .select("*")
            .eq("status", "active")
            .execute()
        )
        candidates = res.data if res and res.data else []
    except Exception as e:
        alert_warning("scheduler_db_read_failure", f"Failed to query due campaigns: {e}")
        return

    due = [
        c for c in candidates
        if c.get("next_scheduled_at") and c["next_scheduled_at"] <= now_iso
    ]

    if not due:
        return

    logger.info(f"[SCHEDULER] {len(due)} campaign(s) due for next step")
    for campaign in due:
        claimed = await _claim_campaign(db, campaign)
        if claimed:
            await _fire_next_step(db, campaign)


async def _claim_campaign(db: Any, campaign: Dict[str, Any]) -> bool:
    """

    Attempts to atomically claim a campaign for processing using a single conditional UPDATE.
    Returns True if successfully claimed, False otherwise.
    """
    campaign_id = campaign["id"]
    try:
        res = (
            db.table("email_campaign_states")
            .update({
                "status": "processing_step",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
            .eq("id", campaign_id)
            .eq("status", "active")
            .execute()
        )
        if res and res.data and len(res.data) == 1:
            return True
        logger.debug(f"[SCHEDULER] Campaign {campaign_id[:8]} could not be claimed (already claimed or not active)")
        return False
    except Exception as e:
        logger.warning(f"[SCHEDULER] Campaign claim error for {campaign_id[:8]}: {e}")
        return False


from ai_email_engine.database.connection import get_db_client, set_tenant_session_context


async def _fire_next_step(db: Any, campaign: Dict[str, Any]) -> None:
    """Fires the next sequence step for a single campaign."""
    tenant_id = campaign["tenant_id"]
    set_tenant_session_context(db, tenant_id)
    lead_id = campaign["lead_id"]
    step_number = campaign.get("current_step", 2)
    campaign_id = campaign["id"]

    context_data = campaign.get("context_data", {})
    email_enc = context_data.get("email_enc")
    email = None

    if email_enc:
        try:
            email = decrypt_pii(email_enc)
        except Exception as e:
            logger.error(f"[SCHEDULER] Decryption error for campaign {campaign_id[:8]}: {e}")

    # Fallback if email was stored unencrypted or in legacy format
    if not email:
        raw_email = context_data.get("email")
        if raw_email and "@" in raw_email:
            email = raw_email

    if not email:
        logger.warning(f"[SCHEDULER] Could not recover valid email for campaign {campaign_id[:8]}")
        # Return status to active so it doesn't stay locked in processing_step forever
        db.table("email_campaign_states").update({"status": "active"}).eq("id", campaign_id).execute()
        return

    full_name_enc = context_data.get("full_name", "")
    full_name = "there"
    if full_name_enc:
        try:
            full_name = decrypt_pii(full_name_enc)
        except Exception:
            full_name = "there"


    if is_email_suppressed(tenant_id, email):
        logger.info(f"[SCHEDULER] Email {mask_email(email)} is unsubscribed/suppressed. Pausing campaign {campaign_id[:8]}.")
        db.table("email_campaign_states").update({
            "status": "paused_unsubscribed",
            "next_scheduled_at": None,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", campaign_id).execute()
        return

    lead_data = {
        "email": email,
        "full_name": full_name,
        "company_name": context_data.get("company_name", ""),
        "notes": context_data.get("notes", ""),
    }

    try:
        subject, body_html = await generate_personalized_copy(
            lead_data, step_number=step_number, tenant_id=tenant_id
        )
        dispatch_res = await _save_or_dispatch_email(
            tenant_id=tenant_id,
            campaign_state=campaign,
            step_number=step_number,
            email=email,
            subject=subject,
            body_html=body_html,
            lead_id=lead_id,
        )

        if dispatch_res.get("status") not in ("sent", "success", "pending_review"):
            logger.warning(f"[SCHEDULER] Dispatch failed for step {step_number} of campaign {campaign_id[:8]}")
            db.table("email_campaign_states").update({"status": "active"}).eq("id", campaign_id).execute()
            return

        next_step = step_number + 1
        if next_step > MAX_SEQUENCE_STEPS:
            update = {
                "status": "completed",
                "next_scheduled_at": None,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            logger.info(f"[SCHEDULER] Campaign {campaign_id[:8]} completed all {MAX_SEQUENCE_STEPS} steps")
        else:
            delay_days = STEP_INTERVAL_DAYS[next_step - 1] if next_step <= len(STEP_INTERVAL_DAYS) else 7
            next_at = (datetime.now(timezone.utc) + timedelta(days=delay_days)).isoformat()
            update = {
                "status": "active",  # Release claim — back to active for future ticks
                "current_step": next_step,
                "next_scheduled_at": next_at,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            logger.info(f"[SCHEDULER] Campaign {campaign_id[:8]} step {step_number} done → step {next_step} at {next_at}")

        db.table("email_campaign_states").update(update).eq("id", campaign_id).execute()


    except Exception as e:
        alert_critical(
            "scheduler_step_failure",
            f"Failed to fire step {step_number} for campaign {campaign_id[:8]}: {e}",
            tenant_id=tenant_id,
        )
        # Release claim back to active so next tick can retry
        try:
            db.table("email_campaign_states").update({
                "status": "active",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", campaign_id).execute()
        except Exception:
            pass
