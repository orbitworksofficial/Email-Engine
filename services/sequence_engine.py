import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from ai_email_engine.database.connection import get_db_client
from ai_email_engine.services.ai_copywriter import generate_personalized_copy
from ai_email_engine.services.resend_dispatcher import send_transactional_email
from ai_email_engine.services.analytics import track_ga4_event
from ai_email_engine.services.alerting import alert_critical, alert_warning
from ai_email_engine.security.pii_crypto import mask_email, encrypt_pii, decrypt_pii, sanitize_input_string, hash_pii_for_lookup
from ai_email_engine.security.rls_middleware import get_request_id
from ai_email_engine.config import settings

logger = logging.getLogger("ai_email_engine.services.sequence_engine")

REQUIRE_EMAIL_APPROVAL = getattr(settings, "REQUIRE_EMAIL_APPROVAL", False)


def is_email_suppressed(tenant_id: str, email: str) -> bool:
    """
    Checks tenant suppression list using a deterministic keyed HMAC hash for lookup.
    Fernet encryption is non-deterministic so we use hash_pii_for_lookup() for comparison.
    """
    db = get_db_client()
    try:
        lookup_hash = hash_pii_for_lookup(email)
        res = (
            db.table("suppression_list")
            .select("id")
            .eq("tenant_id", tenant_id)
            .eq("email", lookup_hash)
            .execute()
        )
        if res and res.data:
            logger.info(f"[{get_request_id()}] Email {mask_email(email)} is suppressed. Skipping.")
            return True
    except Exception as e:
        alert_warning("suppression_check_error", f"Suppression list check failed: {e}", tenant_id=tenant_id)
    return False


async def _save_or_dispatch_email(
    tenant_id: str,
    campaign_state: Dict[str, Any],
    step_number: int,
    email: str,
    subject: str,
    body_html: str,
    lead_id: str,
) -> Dict[str, Any]:
    """
    Issue 7 — Human-in-the-loop gate.
    If REQUIRE_EMAIL_APPROVAL is True, saves to email_drafts for review.
    Otherwise dispatches immediately.
    """
    request_id = get_request_id()
    db = get_db_client()
    campaign_state_id = campaign_state["id"]

    # Pre-dispatch idempotency check against email_logs
    try:
        existing_logs = (
            db.table("email_logs")
            .select("id, resend_message_id, status")
            .eq("tenant_id", tenant_id)
            .eq("campaign_state_id", campaign_state_id)
            .eq("step_number", step_number)
            .execute()
        )
        if existing_logs and existing_logs.data:
            logger.info(f"[{request_id}] Email step {step_number} already logged for campaign {campaign_state_id[:8]} — skipping dispatch")
            return {
                "id": existing_logs.data[0].get("resend_message_id", "already_sent"),
                "status": existing_logs.data[0].get("status", "sent"),
                "mock": False,
            }
    except Exception as e:
        logger.warning(f"[{request_id}] Pre-dispatch email_logs check note: {e}")

    if REQUIRE_EMAIL_APPROVAL:
        draft = {
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "campaign_state_id": campaign_state_id,
            "step_number": step_number,
            "recipient_email": encrypt_pii(email),
            "subject": subject,
            "body_html": body_html,
            "status": "pending_review",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            db.table("email_drafts").insert(draft).execute()
        except Exception as e:
            alert_critical("draft_insert_failure", f"Failed to save email draft: {e}", tenant_id=tenant_id, request_id=request_id)
        logger.info(f"[{request_id}] Email draft saved for manual approval (step {step_number})")
        return {"id": draft["id"], "status": "pending_review", "mock": False}

    # Direct dispatch
    dispatch_res = await send_transactional_email(
        tenant_id=tenant_id,
        recipient_email=email,
        subject=subject,
        body_html=body_html,
    )

    if dispatch_res.get("status") == "failed":
        alert_critical(
            "email_send_failure",
            f"Step {step_number} send failed for {mask_email(email)}",
            tenant_id=tenant_id,
            request_id=request_id,
        )

    log_entry = {
        "id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "campaign_state_id": campaign_state_id,
        "step_number": step_number,
        "resend_message_id": dispatch_res.get("id"),
        "recipient_email": encrypt_pii(email),
        "subject": subject,
        "body_html": body_html,
        "status": dispatch_res.get("status", "sent"),
        "sent_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        db.table("email_logs").insert(log_entry).execute()
    except Exception as e:
        err_str = str(e).lower()
        if "unique" in err_str or "duplicate" in err_str or "23505" in err_str:
            logger.info(f"[{request_id}] Duplicate log entry caught by DB constraint")
        else:
            alert_critical("email_log_insert_failure", f"Failed to write email log: {e}", tenant_id=tenant_id, request_id=request_id)

    await track_ga4_event(
        tenant_id=tenant_id,
        event_name="ai_email_sent",
        params={"lead_id": lead_id, "sequence_step": step_number, "resend_message_id": dispatch_res.get("id")},
    )
    return dispatch_res


async def process_new_lead_sequence(
    tenant_id: str, channel_source: str, payload: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Ingests a new lead, creates campaign state, generates Step 1 copy, and dispatches/drafts email.
    """
    request_id = get_request_id()
    db = get_db_client()

    email = payload.get("email") or payload.get("recipient_email")
    full_name = sanitize_input_string(payload.get("full_name") or payload.get("name") or "Valued Lead")
    lead_id = payload.get("lead_id") or f"lead_{uuid.uuid4().hex[:12]}"

    if not email:
        if payload.get("requires_api_fetch"):
            logger.warning(
                f"[{request_id}] [LINKEDIN ENRICHMENT PENDING] Lead ID {lead_id} requires LinkedIn API fetch — persisting pending_enrichment state"
            )
            campaign_id = str(uuid.uuid4())
            now_iso = datetime.now(timezone.utc).isoformat()
            try:
                db.table("email_campaign_states").insert({
                    "id": campaign_id,
                    "tenant_id": tenant_id,
                    "lead_id": lead_id,
                    "channel_source": channel_source,
                    "status": "pending_enrichment",
                    "context_data": {"requires_api_fetch": True, "raw_payload": payload},
                    "created_at": now_iso,
                    "updated_at": now_iso,
                }).execute()
            except Exception as e:
                logger.warning(f"[{request_id}] Failed to persist pending_enrichment campaign state: {e}")

            return {
                "status": "pending_enrichment",
                "message": "Lead queued for LinkedIn API enrichment",
                "lead_id": lead_id,
                "campaign_id": campaign_id,
            }

        logger.error(f"[{request_id}] Missing lead email in payload")
        return {"status": "permanent_error", "retryable": False, "message": "Email is required"}

    # 1. Suppression check
    if is_email_suppressed(tenant_id, email):
        return {"status": "suppressed", "message": "Lead email is suppressed"}

    # 2. Get or create campaign state (using indexed email_hash column lookup)
    email_hash = hash_pii_for_lookup(email)
    email_enc = encrypt_pii(email)
    campaign_state = None
    try:
        # Indexed lookup by tenant_id + email_hash
        res = (
            db.table("email_campaign_states")
            .select("*")
            .eq("tenant_id", tenant_id)
            .eq("email_hash", email_hash)
            .execute()
        )
        if res and res.data:
            campaign_state = res.data[0]
        else:
            # Fallback lookup by lead_id
            res_lead = (
                db.table("email_campaign_states")
                .select("*")
                .eq("tenant_id", tenant_id)
                .eq("lead_id", lead_id)
                .execute()
            )
            if res_lead and res_lead.data:
                campaign_state = res_lead.data[0]

        if campaign_state:
            terminal = {"paused_booked", "paused_replied", "paused_unsubscribed", "bounced"}
            if campaign_state.get("status") in terminal:
                logger.info(f"[{request_id}] Campaign halted: status={campaign_state['status']}")
                return {"status": "halted", "campaign_status": campaign_state["status"]}
    except Exception as e:
        alert_warning("campaign_state_read_error", f"Campaign state lookup error: {e}", tenant_id=tenant_id, request_id=request_id)

    if not campaign_state:
        safe_context = dict(payload)
        safe_context["email_enc"] = email_enc
        safe_context["email_hash"] = email_hash
        safe_context["email"] = email_hash
        if "full_name" in safe_context:
            safe_context["full_name"] = encrypt_pii(safe_context["full_name"])
        if "name" in safe_context:
            safe_context["name"] = encrypt_pii(safe_context["name"])

        now = datetime.now(timezone.utc).isoformat()
        campaign_state = {
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "lead_id": lead_id,
            "email_hash": email_hash,
            "channel_source": channel_source,
            "utm_source": payload.get("utm_source", channel_source),
            "utm_medium": payload.get("utm_medium", "cpc"),
            "utm_campaign": payload.get("utm_campaign"),
            "gclid": payload.get("gclid"),
            "current_step": 1,
            "status": "active",
            "context_data": safe_context,
            "created_at": now,
            "updated_at": now,
        }
        try:
            db.table("email_campaign_states").insert(campaign_state).execute()
        except Exception as e:
            alert_critical("campaign_state_insert_failure", f"Failed to create campaign state: {e}", tenant_id=tenant_id, request_id=request_id)
            return {"status": "error", "retryable": True, "message": f"Failed to create campaign state: {e}"}

    # 3. GA4 lead_captured
    await track_ga4_event(
        tenant_id=tenant_id,
        event_name="lead_captured",
        params={
            "lead_id": lead_id,
            "source": campaign_state.get("utm_source"),
            "medium": campaign_state.get("utm_medium"),
            "campaign": campaign_state.get("utm_campaign"),
            "gclid": campaign_state.get("gclid"),
            "channel": channel_source,
        },
    )

    # 4. Generate Step 1 copy
    subject, body_html = await generate_personalized_copy(payload, step_number=1, tenant_id=tenant_id)

    # 5. Dispatch or draft
    result = await _save_or_dispatch_email(
        tenant_id=tenant_id,
        campaign_state=campaign_state,
        step_number=1,
        email=email,
        subject=subject,
        body_html=body_html,
        lead_id=lead_id,
    )

    # 6. Advance state — set next step scheduled time only on successful send/draft
    if result.get("status") in ("sent", "success", "pending_review"):
        from datetime import timedelta
        next_scheduled = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
        try:
            db.table("email_campaign_states").update({
                "current_step": 2,
                "next_scheduled_at": next_scheduled,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", campaign_state["id"]).execute()
        except Exception as e:
            alert_warning("campaign_state_advance_error", f"Failed to advance step: {e}", tenant_id=tenant_id, request_id=request_id)
    else:
        logger.warning(f"[{request_id}] Step 1 dispatch failed (status={result.get('status')}) — not advancing campaign step")

    return {"status": "success", "campaign_state_id": campaign_state["id"], "message_id": result.get("id")}


async def handle_calendly_booking_event(tenant_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handles Calendly booking — pauses the specific lead's campaign, fires GA4 meeting_booked."""
    request_id = get_request_id()
    db = get_db_client()
    event_payload = payload.get("payload", {})
    invitee = event_payload.get("invitee", {})
    invitee_email = event_payload.get("email") or invitee.get("email")
    event_uri = event_payload.get("event") or event_payload.get("uri")
    scheduled_time = event_payload.get("start_time") or event_payload.get("scheduled_at")

    if not invitee_email:
        return {"status": "permanent_error", "retryable": False, "message": "Missing invitee email"}

    logger.info(f"[{request_id}] Calendly booking for {mask_email(invitee_email)} → paused_booked")

    # Fix N1: indexed lookup by tenant_id + email_hash
    email_hash = hash_pii_for_lookup(invitee_email)
    try:
        res = db.table("email_campaign_states").select("id, email_hash, context_data").eq("tenant_id", tenant_id).execute()
        matching_ids = [
            row["id"] for row in (res.data or [])
            if row.get("email_hash") == email_hash
               or row.get("context_data", {}).get("email_hash") == email_hash
               or row.get("context_data", {}).get("email") == email_hash
        ]
        if not matching_ids:
            logger.warning(f"[{request_id}] No campaign found for Calendly invitee {mask_email(invitee_email)}")
        for campaign_id in matching_ids:
            db.table("email_campaign_states").update({
                "status": "paused_booked",
                "calendly_event_uri": event_uri,
                "meeting_scheduled_at": scheduled_time,
                "next_scheduled_at": None,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", campaign_id).execute()
    except Exception as e:
        alert_warning("calendly_pause_failure", f"Failed to pause campaign: {e}", tenant_id=tenant_id, request_id=request_id)

    await track_ga4_event(
        tenant_id=tenant_id,
        event_name="meeting_booked",
        params={"invitee_email": invitee_email, "event_uri": event_uri, "scheduled_time": scheduled_time},
    )
    return {"status": "success", "message": f"Sequence paused (paused_booked) for {mask_email(invitee_email)}"}


async def handle_resend_webhook_event(tenant_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handles Resend delivery callbacks: opened, bounced, complained, replied.
    Fix N1: all state updates match specific lead campaign by email_hash column or context_data.
    """
    request_id = get_request_id()
    db = get_db_client()
    event_type = payload.get("type", "")
    event_data = payload.get("data", {})
    to_field = event_data.get("to", [])
    email = to_field[0] if isinstance(to_field, list) and to_field else event_data.get("to")

    if not email:
        return {"status": "success", "event_type": event_type}

    email_hash = hash_pii_for_lookup(email)

    def _find_campaign_ids() -> list:
        """Returns campaign IDs for this specific lead via indexed query or context_data fallback."""
        try:
            res = db.table("email_campaign_states").select("id, email_hash, context_data").eq("tenant_id", tenant_id).execute()
            return [
                row["id"] for row in (res.data or [])
                if row.get("email_hash") == email_hash
                   or row.get("context_data", {}).get("email_hash") == email_hash
                   or row.get("context_data", {}).get("email") == email_hash
            ]
        except Exception as e:
            logger.warning(f"[{request_id}] Campaign lookup error for Resend event: {e}")
            return []




    if event_type == "email.opened":
        await track_ga4_event(tenant_id=tenant_id, event_name="ai_email_opened",
                              params={"email": mask_email(email)})

    elif event_type in ("email.bounced", "email.complained"):
        try:
            db.table("suppression_list").insert({
                "tenant_id": tenant_id,
                "email": hash_pii_for_lookup(email),
                "reason": event_type,
            }).execute()
        except Exception as e:
            if "unique" not in str(e).lower():
                logger.debug(f"[{request_id}] Suppression insert note: {e}")
        for campaign_id in _find_campaign_ids():
            try:
                db.table("email_campaign_states").update({
                    "status": "bounced",
                    "next_scheduled_at": None,
                    "bounced_at": datetime.now(timezone.utc).isoformat(),
                }).eq("id", campaign_id).execute()
            except Exception as e:
                alert_warning("bounce_state_update_failure", f"Failed to update bounce status: {e}", tenant_id=tenant_id)

    elif event_type == "email.replied":
        for campaign_id in _find_campaign_ids():
            try:
                db.table("email_campaign_states").update({
                    "status": "paused_replied",
                    "next_scheduled_at": None,
                    "reply_detected_at": datetime.now(timezone.utc).isoformat(),
                }).eq("id", campaign_id).execute()
            except Exception as e:
                alert_warning("reply_state_update_failure", f"Failed to update reply status: {e}", tenant_id=tenant_id)

    return {"status": "success", "event_type": event_type}
