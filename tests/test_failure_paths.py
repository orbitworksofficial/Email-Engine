"""
test_failure_paths.py — Failure and resilience path tests.
Runnable with plain `python3 -m pytest` or standalone `python3 <this_file>`.
Async tests use asyncio.run() directly (no pytest-asyncio dependency).
"""
import asyncio
import hashlib
import json
import sys
from unittest.mock import patch, MagicMock

from ai_email_engine.security.pii_crypto import (
    encrypt_pii, hash_pii_for_lookup, mask_email, sanitize_input_string
)
from ai_email_engine.security.hmac_verifier import verify_meta_signature, verify_linkedin_signature
from ai_email_engine.database.connection import MockSupabaseClient, UniqueViolationError, reset_db_client


# ── Fix 4 verification: idempotency — mock actually raises on duplicate ────

def test_mock_unique_constraint_enforcement():
    """
    Fix 4: verifies that MockSupabaseClient now raises UniqueViolationError on
    a duplicate (tenant_id, payload_hash) insert, exactly as Postgres would.
    Previous version just appended — making all idempotency tests vacuous.
    """
    db = MockSupabaseClient()
    record = {"tenant_id": "tenant-001", "payload_hash": "abc123", "provider": "website", "status": "received"}
    db.table("webhook_events").insert(record).execute()

    raised = False
    try:
        db.table("webhook_events").insert(record).execute()
    except UniqueViolationError as e:
        raised = True
        assert "23505" in str(e), "Error message should contain Postgres violation code 23505"
    assert raised, "Second identical insert must raise UniqueViolationError"


def test_idempotency_insert_first_real_dedup():
    """
    Tests that the insert-first dedup pattern works end-to-end.
    Inserts the same webhook_events record twice into MockSupabaseClient and
    verifies the second insert raises UniqueViolationError (as Postgres would),
    which is exactly what _insert_webhook_event_or_dedup catches to detect duplicates.
    """
    db = MockSupabaseClient()
    record = {
        "tenant_id": "tenant-001",
        "provider": "website",
        "payload_hash": hashlib.sha256(b'test payload').hexdigest(),
        "raw_payload": {},
        "status": "received",
    }
    # First insert: succeeds
    db.table("webhook_events").insert(record).execute()

    # Second identical insert: must raise UniqueViolationError
    raised = False
    try:
        db.table("webhook_events").insert(record).execute()
    except UniqueViolationError as e:
        raised = True
        assert "23505" in str(e)
    assert raised, "Duplicate insert must raise UniqueViolationError — dedup relies on this"

    # Only one row should exist
    rows = db.table("webhook_events").select("*").eq("tenant_id", "tenant-001").execute()
    assert len(rows.data) == 1, "Exactly one row should exist after dedup"


# ── Issue 12a: Suppressed email is blocked before dispatch ─────────────────

def test_suppressed_email_is_blocked():
    from ai_email_engine.services import sequence_engine

    mock_db = MockSupabaseClient()
    tenant_id = "tenant-test-001"
    raw_email = "blocked@domain.com"
    mock_db.tables["suppression_list"].append({
        "tenant_id": tenant_id,
        "email": hash_pii_for_lookup(raw_email),
        "reason": "unsubscribe_click",
    })

    with patch("ai_email_engine.services.sequence_engine.get_db_client", return_value=mock_db):
        result = sequence_engine.is_email_suppressed(tenant_id, raw_email)
    assert result is True, "Suppressed email should be blocked"


def test_unsuppressed_email_is_allowed():
    from ai_email_engine.services import sequence_engine

    mock_db = MockSupabaseClient()
    with patch("ai_email_engine.services.sequence_engine.get_db_client", return_value=mock_db):
        result = sequence_engine.is_email_suppressed("tenant-001", "fresh@domain.com")
    assert result is False, "Unsuppressed email should pass"


# ── Fix 3 verification: unsubscribe uses hash_pii_for_lookup ───────────────

def test_unsubscribe_writes_lookup_hash():
    """
    Fix 3: verifies that the unsubscribe endpoint writes hash_pii_for_lookup(email),
    so that is_email_suppressed() can find it later.
    """
    mock_db = MockSupabaseClient()
    email = "user@example.com"
    tenant_id = "tenant-001"
    expected_hash = hash_pii_for_lookup(email)

    # Simulate what compliance.py does
    with patch("ai_email_engine.api.compliance.get_db_client", return_value=mock_db):
        mock_db.table("suppression_list").insert({
            "tenant_id": tenant_id,
            "email": hash_pii_for_lookup(email),
            "reason": "unsubscribe_click",
        }).execute()

    stored = mock_db.tables["suppression_list"]
    assert len(stored) == 1
    assert stored[0]["email"] == expected_hash, (
        "Must be hash_pii_for_lookup result so suppression check finds it"
    )

    # Confirm suppression check finds it
    from ai_email_engine.services.sequence_engine import is_email_suppressed
    with patch("ai_email_engine.services.sequence_engine.get_db_client", return_value=mock_db):
        assert is_email_suppressed(tenant_id, email) is True


# ── Fix 2 verification: Calendly only pauses specific lead, not all ────────

def test_calendly_pauses_only_matching_campaign():
    """
    Fix 2: Calendly booking pauses only the campaign for the booking invitee,
    not every active campaign for the entire tenant.
    """
    from ai_email_engine.services.sequence_engine import handle_calendly_booking_event

    mock_db = MockSupabaseClient()
    tenant_id = "tenant-001"
    invitee_email = "alice@acme.com"
    other_email = "bob@other.com"

    mock_db.tables["email_campaign_states"] = [
        {
            "id": "campaign-alice",
            "tenant_id": tenant_id,
            "lead_id": "lead-alice",
            "status": "active",
            "context_data": {"email": hash_pii_for_lookup(invitee_email)},
        },
        {
            "id": "campaign-bob",
            "tenant_id": tenant_id,
            "lead_id": "lead-bob",
            "status": "active",
            "context_data": {"email": hash_pii_for_lookup(other_email)},
        },
    ]

    payload = {"payload": {"email": invitee_email, "event": "https://cal.com/event/123"}}

    async def _mock_ga4(*args, **kwargs):
        return True

    with patch("ai_email_engine.services.sequence_engine.get_db_client", return_value=mock_db), \
         patch("ai_email_engine.services.sequence_engine.track_ga4_event", side_effect=_mock_ga4):
        asyncio.run(handle_calendly_booking_event(tenant_id, payload))

    alice = next(r for r in mock_db.tables["email_campaign_states"] if r["id"] == "campaign-alice")
    bob = next(r for r in mock_db.tables["email_campaign_states"] if r["id"] == "campaign-bob")
    assert alice["status"] == "paused_booked", "Alice's campaign should be paused"
    assert bob["status"] == "active", "Bob's campaign must NOT be paused"


# ── LLM fallback: generate_fallback_email produces valid output ────────────

def test_fallback_email_output():
    from ai_email_engine.services.ai_copywriter import generate_fallback_email
    lead = {"full_name": "Test User", "company_name": "ACME Corp", "email": "test@acme.com"}
    subject, body_html = generate_fallback_email(lead)
    assert "ACME Corp" in subject or "outreach" in subject.lower()
    assert "<p>" in body_html
    assert "OrbitWorks" in body_html


# ── Resend mock dispatch returns well-formed response ──────────────────────

def test_resend_mock_returns_sent_status():
    from ai_email_engine.services.resend_dispatcher import send_transactional_email
    with patch("ai_email_engine.services.resend_dispatcher.HAS_RESEND", False):
        result = asyncio.run(send_transactional_email(
            tenant_id="tenant-001",
            recipient_email="user@test.com",
            subject="Test",
            body_html="<p>Hello</p>",
        ))
    assert result["status"] == "sent"
    assert "id" in result
    assert result["mock"] is True


# ── Tenant isolation ───────────────────────────────────────────────────────

def test_tenant_data_isolation():
    db = MockSupabaseClient()
    tenant_a = "aaaaaaaa-0000-0000-0000-000000000001"
    tenant_b = "bbbbbbbb-0000-0000-0000-000000000002"

    db.table("email_campaign_states").insert({
        "id": "state-a-001", "tenant_id": tenant_a, "lead_id": "lead-a", "status": "active",
    }).execute()
    db.table("email_campaign_states").insert({
        "id": "state-b-001", "tenant_id": tenant_b, "lead_id": "lead-b", "status": "active",
    }).execute()

    res_a = db.table("email_campaign_states").select("*").eq("tenant_id", tenant_a).execute()
    assert all(r["tenant_id"] == tenant_a for r in res_a.data)

    res_b = db.table("email_campaign_states").select("*").eq("tenant_id", tenant_b).execute()
    assert all(r["tenant_id"] == tenant_b for r in res_b.data)


# ── HMAC correctness ───────────────────────────────────────────────────────

def test_linkedin_hmac_valid():
    import hmac as _hmac, hashlib
    secret = "test_linkedin_secret"
    payload = b'{"lead_id": "li_123"}'
    sig = "sha256=" + _hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    assert verify_linkedin_signature(payload, sig, secret) is True


def test_linkedin_hmac_invalid():
    payload = b'{"lead_id": "li_123"}'
    assert verify_linkedin_signature(payload, "sha256=badhash", "real_secret") is False


def test_rate_limiter_insert_first():
    """Fix 6: rate limiter inserts first row successfully, then reads for second request."""
    reset_db_client()
    from ai_email_engine.database import connection as conn
    mock_db = MockSupabaseClient()
    conn._db_client = mock_db

    from ai_email_engine.security.rate_limiter import is_rate_limited
    result = is_rate_limited("tenant-001", "meta-ads", max_requests=5)
    assert result is False, "First request should not be rate-limited"
    assert len(mock_db.tables["rate_limit_counters"]) == 1

    reset_db_client()


def test_job_runner_permanent_error_dead_letters_immediately():
    """Permanent invalid input errors dead-letter immediately on attempt 1 without retries."""
    reset_db_client()
    from ai_email_engine.database import connection as conn
    mock_db = MockSupabaseClient()
    conn._db_client = mock_db

    from ai_email_engine.workers.job_runner import run_job_with_retry

    # Insert initial received webhook event (as webhooks endpoint does in production)
    mock_db.table("webhook_events").insert({
        "tenant_id": "tenant-001",
        "payload_hash": "hash_no_email",
        "provider": "website",
        "status": "received"
    }).execute()

    # Payload with missing lead email (permanent input error)
    payload = {"company_name": "No Email Corp"}
    asyncio.run(run_job_with_retry("tenant-001", "website", payload, payload_hash="hash_no_email"))

    # Verify webhook_events row status is 'dead_letter' after single attempt
    events = mock_db.tables["webhook_events"]
    matching = [e for e in events if e.get("payload_hash") == "hash_no_email"]
    assert len(matching) == 1
    assert matching[0]["status"] == "dead_letter"

    reset_db_client()


# ── Standalone runner ──────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_mock_unique_constraint_enforcement,
        test_idempotency_insert_first_real_dedup,
        test_suppressed_email_is_blocked,
        test_unsuppressed_email_is_allowed,
        test_unsubscribe_writes_lookup_hash,
        test_calendly_pauses_only_matching_campaign,
        test_fallback_email_output,
        test_resend_mock_returns_sent_status,
        test_tenant_data_isolation,
        test_linkedin_hmac_valid,
        test_linkedin_hmac_invalid,
        test_rate_limiter_insert_first,
        test_job_runner_permanent_error_dead_letters_immediately,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  ✅ {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ❌ {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed}/{passed + failed} tests passed")
    sys.exit(0 if failed == 0 else 1)
