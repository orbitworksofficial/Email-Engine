import hashlib
import json
import logging
from typing import Optional, Tuple

from fastapi import APIRouter, Request, HTTPException, Header, Query, Depends
from fastapi.responses import PlainTextResponse, JSONResponse

from ai_email_engine.config import settings
from ai_email_engine.security.hmac_verifier import (
    verify_meta_signature,
    verify_calendly_signature,
    verify_google_lead_secret,
    verify_linkedin_signature,
    verify_website_signature,
)
from ai_email_engine.security.api_key_auth import optional_api_key
from ai_email_engine.security.rate_limiter import is_rate_limited
from ai_email_engine.database.connection import get_db_client, set_tenant_session_context
from ai_email_engine.workers.job_runner import run_job_with_retry
from ai_email_engine.security.rls_middleware import get_request_id
from ai_email_engine.api.schemas import (
    MetaLeadFormPayload,
    LinkedInLeadPayload,
    GoogleAdsLeadPayload,
    WebsiteLeadPayload,
    CalendlyWebhookPayload,
    ResendEventPayload,
)

logger = logging.getLogger("ai_email_engine.webhooks")
router = APIRouter(prefix="/api/v1/webhooks", tags=["Webhooks Gateway"])


def _get_tenant_id(api_key_tenant: Optional[str]) -> str:
    """
    Resolves tenant_id from the authenticated API key.
    Falls back to DEFAULT_TENANT_ID only in non-production environments.
    Executes set_tenant_session_context to enforce Postgres RLS session context.
    """
    if api_key_tenant:
        tenant_id = api_key_tenant
    elif settings.ENVIRONMENT != "production":
        tenant_id = settings.DEFAULT_TENANT_ID
    else:
        raise HTTPException(status_code=401, detail="Valid X-API-Key required in production")

    set_tenant_session_context(get_db_client(), tenant_id)
    return tenant_id


def _should_verify_signatures() -> bool:
    if settings.ALLOW_UNSIGNED_WEBHOOKS and settings.ENVIRONMENT != "production":
        return False
    return True


from pydantic import ValidationError
from ai_email_engine.api.schemas import LinkedInIDOnlyPayload


def _validate_webhook_payload(provider: str, raw_body: bytes) -> dict:
    """
    Parses raw_body into JSON and validates against provider Pydantic schemas.
    Raises HTTPException(422) if validation fails.
    """
    payload = _parse_json_payload(raw_body)
    normalized = extract_provider_lead_payload(provider, payload)
    try:
        if provider == "website":
            WebsiteLeadPayload(**normalized)
        elif provider == "meta_ads":
            MetaLeadFormPayload(**normalized)
        elif provider == "linkedin_ads":
            if normalized.get("requires_api_fetch"):
                LinkedInIDOnlyPayload(**normalized)
            else:
                LinkedInLeadPayload(**normalized)
        elif provider == "google_ads":
            GoogleAdsLeadPayload(**normalized)
        elif provider == "calendly":
            CalendlyWebhookPayload(**payload)
        elif provider == "resend":
            ResendEventPayload(**payload)
    except ValidationError as ve:
        logger.warning(f"Webhook payload Pydantic validation error for {provider}: {ve}")
        raise HTTPException(status_code=422, detail=f"Invalid payload schema for {provider}: {ve}")
    except Exception as e:
        logger.warning(f"Payload validation parsing error for {provider}: {e}")
        raise HTTPException(status_code=422, detail=f"Malformed payload for {provider}: {e}")

    return payload


def _parse_json_payload(raw_body: bytes) -> dict:
    if not raw_body:
        return {}
    try:
        return json.loads(raw_body.decode("utf-8"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Malformed JSON payload: {e}")


def extract_provider_lead_payload(provider: str, payload: dict) -> dict:
    """
    Normalizes provider-specific payload shapes into a standard lead dictionary.
    Handles Meta Ads (nested entry/field_data), LinkedIn Ads (formResponse/answers), and Google Ads (user_column_data).
    """
    if not isinstance(payload, dict):
        return {}

    if provider == "meta_ads" and "entry" in payload:
        try:
            entry = payload.get("entry", [])[0]
            change = entry.get("changes", [])[0]
            val = change.get("value", {})
            if isinstance(val, dict):
                fields = {}
                if "field_data" in val and isinstance(val["field_data"], list):
                    for f in val["field_data"]:
                        name = f.get("name")
                        values = f.get("values", [])
                        if name and values:
                            fields[name] = values[0]
                return {
                    "lead_id": val.get("leadgen_id") or val.get("lead_id"),
                    "form_id": val.get("form_id"),
                    "created_time": val.get("created_time"),
                    "email": fields.get("email") or val.get("email"),
                    "full_name": fields.get("full_name") or (fields.get("first_name", "") + " " + fields.get("last_name", "")).strip() or val.get("full_name"),
                    "company_name": fields.get("company_name") or val.get("company_name"),
                    "utm_campaign": val.get("utm_campaign"),
                }
        except Exception:
            pass

    if provider == "linkedin_ads":
        if "formResponse" in payload or "answers" in payload:
            try:
                answers = payload.get("answers") or payload.get("formResponse", {}).get("answers", [])
                fields = {}
                for ans in answers:
                    field_id = str(ans.get("fieldId") or ans.get("columnName", "")).lower()
                    values = ans.get("values", [])
                    if field_id and values:
                        fields[field_id] = values[0]
                return {
                    "lead_id": payload.get("lead_id") or payload.get("leadGenId") or payload.get("id"),
                    "form_id": payload.get("form_id") or payload.get("formId"),
                    "email": fields.get("email") or fields.get("email_address") or payload.get("email"),
                    "full_name": fields.get("full_name") or fields.get("name") or payload.get("full_name"),
                    "company_name": fields.get("company_name") or fields.get("company") or payload.get("company_name"),
                    "job_title": fields.get("job_title") or fields.get("title") or payload.get("job_title"),
                    "utm_campaign": payload.get("utm_campaign"),
                }
            except Exception:
                pass

        lead_id = payload.get("lead_id") or payload.get("leadGenId") or payload.get("leadgen_id") or payload.get("id")
        if lead_id:
            return {
                "lead_id": lead_id,
                "form_id": payload.get("form_id") or payload.get("formId"),
                "email": payload.get("email"),
                "full_name": payload.get("full_name"),
                "company_name": payload.get("company_name"),
                "requires_api_fetch": True if not payload.get("email") else False,
            }

    if provider == "google_ads" and "user_column_data" in payload:
        try:
            fields = {}
            for col in payload.get("user_column_data", []):
                col_name = str(col.get("column_name") or col.get("type", "")).lower()
                val = col.get("string_value") or col.get("column_value")
                if col_name and val:
                    fields[col_name] = val
            return {
                "lead_id": payload.get("lead_id") or payload.get("gclid") or payload.get("google_key"),
                "gclid": payload.get("gclid"),
                "email": fields.get("email") or fields.get("user_email") or payload.get("email"),
                "full_name": fields.get("full_name") or (fields.get("first_name", "") + " " + fields.get("last_name", "")).strip() or payload.get("full_name"),
                "company_name": fields.get("company_name") or payload.get("company_name"),
                "utm_campaign": payload.get("utm_campaign"),
            }
        except Exception:
            pass

    return payload



def _insert_webhook_event_or_dedup(
    tenant_id: str, provider: str, raw_body: bytes, event_id: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Insert-first idempotency pattern.
    Attempts INSERT immediately. Catches unique-violation as a clean dedup signal.
    Returns (is_duplicate, payload_hash).
    """
    payload_hash = hashlib.sha256(raw_body).hexdigest()
    db = get_db_client()
    try:
        parsed_payload = _parse_json_payload(raw_body)
    except HTTPException:
        parsed_payload = {}
    try:
        db.table("webhook_events").insert({
            "tenant_id": tenant_id,
            "provider": provider,
            "event_id": event_id,
            "payload_hash": payload_hash,
            "raw_payload": parsed_payload,
            "status": "received",
        }).execute()
        return False, payload_hash
    except Exception as e:
        err_str = str(e).lower()
        if "unique" in err_str or "23505" in err_str or "duplicate" in err_str:
            logger.info(f"[{get_request_id()}] Duplicate webhook deduped: hash={payload_hash[:8]}")
            return True, payload_hash
        logger.warning(f"[{get_request_id()}] Webhook insert error (proceeding): {e}")
        return False, payload_hash


def _check_rate_limit(tenant_id: str, endpoint: str) -> None:
    if is_rate_limited(tenant_id, endpoint):
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded for '{endpoint}'")


# ── Meta Ads ─────────────────────────────────────────────────────────────────

@router.get("/meta-ads")
async def verify_meta_webhook(
    hub_mode: Optional[str] = Query(None, alias="hub.mode"),
    hub_challenge: Optional[str] = Query(None, alias="hub.challenge"),
    hub_verify_token: Optional[str] = Query(None, alias="hub.verify_token"),
):
    """GET handshake — uses META_WEBHOOK_VERIFY_TOKEN (not the App Secret)."""
    if hub_mode == "subscribe" and hub_verify_token == settings.META_WEBHOOK_VERIFY_TOKEN:
        return PlainTextResponse(hub_challenge)
    raise HTTPException(status_code=403, detail="Meta verify token mismatch")


@router.post("/meta-ads")
async def ingest_meta_lead(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    api_key_tenant: Optional[str] = Depends(optional_api_key),
):
    """POST payload — verified via META_APP_SECRET (App Dashboard → Settings → Basic)."""
    raw_body = await request.body()
    if _should_verify_signatures() and not api_key_tenant:
        if not settings.META_APP_SECRET or settings.META_APP_SECRET == "meta_app_secret_key":
            raise HTTPException(status_code=500, detail="META_APP_SECRET not configured")
        if not verify_meta_signature(raw_body, x_hub_signature_256, settings.META_APP_SECRET):
            raise HTTPException(status_code=401, detail="Invalid Meta HMAC payload signature")

    tenant_id = _get_tenant_id(api_key_tenant)
    _check_rate_limit(tenant_id, "meta-ads")
    is_dup, payload_hash = _insert_webhook_event_or_dedup(tenant_id, "meta_ads", raw_body)
    if is_dup:
        return JSONResponse(status_code=200, content={"status": "success", "message": "Duplicate event ignored"})

    payload = _validate_webhook_payload("meta_ads", raw_body)
    import asyncio
    asyncio.create_task(run_job_with_retry(tenant_id, "meta_ads", payload, payload_hash))
    return JSONResponse(status_code=202, content={"status": "accepted", "message": "Meta lead queued"})


# ── LinkedIn Ads ──────────────────────────────────────────────────────────────

@router.post("/linkedin-ads")
async def ingest_linkedin_lead(
    request: Request,
    x_li_signature: Optional[str] = Header(None, alias="X-LI-Signature"),
    api_key_tenant: Optional[str] = Depends(optional_api_key),
):
    raw_body = await request.body()
    if _should_verify_signatures() and not api_key_tenant:
        if not verify_linkedin_signature(raw_body, x_li_signature, settings.LINKEDIN_ADS_SECRET):
            raise HTTPException(status_code=401, detail="Invalid LinkedIn HMAC signature")

    tenant_id = _get_tenant_id(api_key_tenant)
    _check_rate_limit(tenant_id, "linkedin-ads")
    is_dup, payload_hash = _insert_webhook_event_or_dedup(tenant_id, "linkedin_ads", raw_body)
    if is_dup:
        return JSONResponse(status_code=200, content={"status": "success", "message": "Duplicate event ignored"})

    payload = _validate_webhook_payload("linkedin_ads", raw_body)
    import asyncio
    asyncio.create_task(run_job_with_retry(tenant_id, "linkedin_ads", payload, payload_hash))
    return JSONResponse(status_code=202, content={"status": "accepted", "message": "LinkedIn lead queued"})


# ── Google Ads ────────────────────────────────────────────────────────────────

@router.post("/google-ads")
async def ingest_google_ads_lead(
    request: Request,
    x_google_lead_secret: Optional[str] = Header(None, alias="X-Google-Lead-Secret"),
    api_key_tenant: Optional[str] = Depends(optional_api_key),
):
    raw_body = await request.body()
    if _should_verify_signatures() and not api_key_tenant:
        if not verify_google_lead_secret(x_google_lead_secret, settings.GOOGLE_ADS_LEAD_SECRET):
            raise HTTPException(status_code=401, detail="Invalid Google Lead Secret")

    tenant_id = _get_tenant_id(api_key_tenant)
    _check_rate_limit(tenant_id, "google-ads")
    is_dup, payload_hash = _insert_webhook_event_or_dedup(tenant_id, "google_ads", raw_body)
    if is_dup:
        return JSONResponse(status_code=200, content={"status": "success", "message": "Duplicate event ignored"})

    payload = _validate_webhook_payload("google_ads", raw_body)
    import asyncio
    asyncio.create_task(run_job_with_retry(tenant_id, "google_ads", payload, payload_hash))
    return JSONResponse(status_code=202, content={"status": "accepted", "message": "Google Ads lead queued"})


# ── Calendly ──────────────────────────────────────────────────────────────────

@router.post("/calendly")
async def ingest_calendly_booking(
    request: Request,
    x_calendly_hook_signature: Optional[str] = Header(None, alias="X-Calendly-Hook-Signature"),
    api_key_tenant: Optional[str] = Depends(optional_api_key),
):
    raw_body = await request.body()
    if _should_verify_signatures() and not api_key_tenant:
        if not verify_calendly_signature(raw_body, x_calendly_hook_signature, settings.CALENDLY_WEBHOOK_SECRET):
            raise HTTPException(status_code=401, detail="Invalid Calendly HMAC signature")

    tenant_id = _get_tenant_id(api_key_tenant)
    _check_rate_limit(tenant_id, "calendly")
    is_dup, payload_hash = _insert_webhook_event_or_dedup(tenant_id, "calendly", raw_body)
    if is_dup:
        return JSONResponse(status_code=200, content={"status": "success", "message": "Duplicate event ignored"})

    payload = _validate_webhook_payload("calendly", raw_body)
    import asyncio
    asyncio.create_task(run_job_with_retry(tenant_id, "calendly", payload, payload_hash))
    return JSONResponse(status_code=202, content={"status": "accepted", "message": "Calendly booking queued"})


# ── Website ───────────────────────────────────────────────────────────────────

@router.post("/website")
async def ingest_website_lead(
    request: Request,
    x_webhook_signature: Optional[str] = Header(None, alias="X-Webhook-Signature"),
    api_key_tenant: Optional[str] = Depends(optional_api_key),
):
    raw_body = await request.body()
    if _should_verify_signatures() and not api_key_tenant:
        if not verify_website_signature(raw_body, x_webhook_signature, settings.WEBSITE_WEBHOOK_SECRET):
            raise HTTPException(status_code=401, detail="Invalid website webhook signature")

    tenant_id = _get_tenant_id(api_key_tenant)
    _check_rate_limit(tenant_id, "website")
    is_dup, payload_hash = _insert_webhook_event_or_dedup(tenant_id, "website", raw_body)
    if is_dup:
        return JSONResponse(status_code=200, content={"status": "success", "message": "Duplicate event ignored"})

    payload = _validate_webhook_payload("website", raw_body)
    import asyncio
    asyncio.create_task(run_job_with_retry(tenant_id, "website", payload, payload_hash))
    return JSONResponse(status_code=202, content={"status": "accepted", "message": "Website lead queued"})


# ── Resend Callbacks ──────────────────────────────────────────────────────────

@router.post("/resend")
async def ingest_resend_event(
    request: Request,
    api_key_tenant: Optional[str] = Depends(optional_api_key),
):
    raw_body = await request.body()
    tenant_id = _get_tenant_id(api_key_tenant)
    _check_rate_limit(tenant_id, "resend")
    is_dup, payload_hash = _insert_webhook_event_or_dedup(tenant_id, "resend", raw_body)
    if is_dup:
        return JSONResponse(status_code=200, content={"status": "success", "message": "Duplicate event ignored"})

    payload = _validate_webhook_payload("resend", raw_body)
    import asyncio
    asyncio.create_task(run_job_with_retry(tenant_id, "resend", payload, payload_hash))
    return JSONResponse(status_code=202, content={"status": "accepted", "message": "Resend event queued"})

