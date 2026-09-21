try:
    import pytest
except ImportError:
    pytest = None

from unittest.mock import MagicMock
from ai_email_engine.services.sequence_engine import process_new_lead_sequence, handle_calendly_booking_event
from ai_email_engine.database.connection import get_db_client
from ai_email_engine.config import settings

def mark_asyncio(func):
    return func

async_decorator = pytest.mark.asyncio if pytest else mark_asyncio

@async_decorator
async def test_lead_sequence_dispatch_and_calendly_pause():
    from ai_email_engine.database import connection as conn
    from ai_email_engine.database.connection import MockSupabaseClient, reset_db_client
    mock_db = MockSupabaseClient()
    conn._db_client = mock_db

    tenant_id = settings.DEFAULT_TENANT_ID
    payload = {
        "lead_id": "test_lead_001",
        "email": "sequence_test@orbitworks.ai",
        "full_name": "Sequence Tester",
        "company_name": "Test Labs"
    }

    # 1. Process New Lead Sequence
    res = await process_new_lead_sequence(tenant_id, "website", payload)
    assert res["status"] == "success"
    assert "campaign_state_id" in res

    # 2. Simulate Calendly Booking to trigger 'paused_booked'
    calendly_payload = {
        "payload": {
            "email": "sequence_test@orbitworks.ai",
            "event": "https://api.calendly.com/events/EVT12345",
            "start_time": "2026-09-20T10:00:00Z"
        }
    }
    booking_res = await handle_calendly_booking_event(tenant_id, calendly_payload)
    assert booking_res["status"] == "success"
    assert "paused_booked" in booking_res["message"]

    # 3. Verify Campaign State status in DB
    states = mock_db.table("email_campaign_states").select("*").eq("tenant_id", tenant_id).execute()
    found = [s for s in states.data if s.get("lead_id") == "test_lead_001"]
    reset_db_client()
    assert len(found) > 0
    assert found[0]["status"] == "paused_booked"


from datetime import datetime, timezone, timedelta
from ai_email_engine.workers.sequence_scheduler import _tick_sequence_scheduler
from ai_email_engine.security.pii_crypto import decrypt_pii, hash_pii_for_lookup
from ai_email_engine.api.compliance import generate_unsubscribe_token, verify_unsubscribe_token


@async_decorator
@async_decorator
async def test_scheduler_step2_decryption_and_dispatch():
    from ai_email_engine.database import connection as conn
    from ai_email_engine.database.connection import MockSupabaseClient, reset_db_client
    mock_db = MockSupabaseClient()
    conn._db_client = mock_db

    tenant_id = "00000000-0000-0000-0000-000000000002"
    email = "alice@acme.com"
    payload = {
        "lead_id": "lead_alice_999",
        "email": email,
        "full_name": "Alice Smith",
        "company_name": "Acme Inc"
    }

    # 1. Process step 1
    res = await process_new_lead_sequence(tenant_id, "website", payload)
    assert res["status"] == "success"

    # 2. Advance clock by updating next_scheduled_at to yesterday
    past_iso = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    mock_db.table("email_campaign_states").update({
        "next_scheduled_at": past_iso
    }).eq("tenant_id", tenant_id).execute()

    # 3. Fire scheduler tick
    await _tick_sequence_scheduler()

    # 4. Verify step 2 email log exists and recipient_email decrypts to original address (NOT a hash!)
    logs = mock_db.table("email_logs").select("*").eq("tenant_id", tenant_id).execute()
    step2_logs = [l for l in (logs.data or []) if l.get("step_number") == 2]
    assert len(step2_logs) == 1, "Exactly 1 step 2 log should be dispatched"
    recip_enc = step2_logs[0]["recipient_email"]
    decrypted_recip = decrypt_pii(recip_enc)
    reset_db_client()
    assert decrypted_recip == email, f"Expected {email}, got {decrypted_recip}"


@async_decorator
async def test_unsubscribe_blocks_sequence_step2():
    from ai_email_engine.database import connection as conn
    from ai_email_engine.database.connection import MockSupabaseClient, reset_db_client
    mock_db = MockSupabaseClient()
    conn._db_client = mock_db

    tenant_id = "00000000-0000-0000-0000-000000000003"
    email = "bob@acme.com"
    payload = {
        "lead_id": "lead_bob_888",
        "email": email,
        "full_name": "Bob Jones",
        "company_name": "Jones Corp"
    }

    # 1. Process step 1
    res = await process_new_lead_sequence(tenant_id, "website", payload)
    assert res["status"] == "success"

    # 2. Add bob@acme.com to suppression list
    mock_db.table("suppression_list").insert({
        "tenant_id": tenant_id,
        "email": hash_pii_for_lookup(email),
        "reason": "user_unsubscribe"
    }).execute()

    # 3. Advance clock to due date
    past_iso = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    mock_db.table("email_campaign_states").update({
        "next_scheduled_at": past_iso
    }).eq("tenant_id", tenant_id).execute()

    # 4. Fire scheduler tick
    await _tick_sequence_scheduler()

    # 5. Verify NO step 2 log exists and campaign is paused_unsubscribed
    logs = mock_db.table("email_logs").select("*").eq("tenant_id", tenant_id).execute()
    step2_logs = [l for l in (logs.data or []) if l.get("step_number") == 2]
    assert len(step2_logs) == 0, "No step 2 email should be sent after unsubscribe"

    states = mock_db.table("email_campaign_states").select("*").eq("tenant_id", tenant_id).execute()
    status_val = states.data[0]["status"]
    reset_db_client()
    assert status_val == "paused_unsubscribed"


def test_unsubscribe_signed_token_roundtrip():
    tenant_id = "00000000-0000-0000-0000-000000000001"
    email = "user@domain.com"
    token = generate_unsubscribe_token(tenant_id, email)
    res = verify_unsubscribe_token(token)
    assert res is not None
    assert res[0] == tenant_id
    assert res[1] == hash_pii_for_lookup(email)

    # Tampered token fails
    assert verify_unsubscribe_token(token[:-4] + "XXXX") is None


@async_decorator
async def test_linkedin_id_only_pending_enrichment_persistence():
    from ai_email_engine.database import connection as conn
    from ai_email_engine.database.connection import MockSupabaseClient, reset_db_client
    mock_db = MockSupabaseClient()
    conn._db_client = mock_db

    tenant_id = "00000000-0000-0000-0000-000000000004"
    payload = {
        "lead_id": "li_lead_id_only_999",
        "requires_api_fetch": True,
        "form_id": "form_123"
    }

    # Process ID-only lead sequence
    res = await process_new_lead_sequence(tenant_id, "linkedin_ads", payload)
    assert res["status"] == "pending_enrichment"
    assert "campaign_id" in res

    # Verify campaign state row WAS persisted in DB with status = pending_enrichment
    states = mock_db.table("email_campaign_states").select("*").eq("tenant_id", tenant_id).execute()
    found = [s for s in (states.data or []) if s.get("lead_id") == "li_lead_id_only_999"]
    reset_db_client()
    assert len(found) == 1, "Exactly 1 campaign state row should be persisted for pending_enrichment lead"
    assert found[0]["status"] == "pending_enrichment"
    assert found[0]["channel_source"] == "linkedin_ads"


if __name__ == "__main__":
    import asyncio
    import sys
    tests = [
        test_lead_sequence_dispatch_and_calendly_pause,
        test_scheduler_step2_decryption_and_dispatch,
        test_unsubscribe_blocks_sequence_step2,
        test_linkedin_id_only_pending_enrichment_persistence,
    ]
    passed = failed = 0
    for t in tests:
        try:
            asyncio.run(t())
            print(f"  ✅ {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ❌ {t.__name__}: {e}")
            failed += 1
    try:
        test_unsubscribe_signed_token_roundtrip()
        print("  ✅ test_unsubscribe_signed_token_roundtrip")
        passed += 1
    except Exception as e:
        print(f"  ❌ test_unsubscribe_signed_token_roundtrip: {e}")
        failed += 1

    print(f"\n{passed}/{passed + failed} sequence tests passed")
    sys.exit(0 if failed == 0 else 1)


