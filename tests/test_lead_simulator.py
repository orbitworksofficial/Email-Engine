import asyncio
import logging
from typing import Dict, Any
from ai_email_engine.config import settings
from ai_email_engine.services.sequence_engine import process_new_lead_sequence, handle_calendly_booking_event, handle_resend_webhook_event
from ai_email_engine.security.pii_crypto import mask_email

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("test_lead_simulator")

SIMULATED_LEADS = [
    {
        "channel": "meta_ads",
        "lead_id": "meta_lead_991",
        "email": "sarah.meta@acme.org",
        "full_name": "Sarah Connor",
        "company_name": "Cyberdyne Systems",
        "utm_campaign": "meta_retargeting_q3"
    },
    {
        "channel": "linkedin_ads",
        "lead_id": "linkedin_lead_882",
        "email": "alex.linkedin@enterprise.io",
        "full_name": "Alex Mercer",
        "company_name": "Enterprise AI Tech",
        "utm_campaign": "linkedin_b2b_execs"
    },
    {
        "channel": "google_ads",
        "lead_id": "google_lead_773",
        "email": "david.google@growth.co",
        "full_name": "David Miller",
        "company_name": "Growth Acceleration Inc",
        "gclid": "TeSt_GcLiD_1234567890",
        "utm_campaign": "google_search_intent"
    },
    {
        "channel": "website",
        "lead_id": "web_lead_664",
        "email": "elena.web@innovate.net",
        "full_name": "Elena Rostova",
        "company_name": "Innovate Labs",
        "utm_campaign": "direct_website_form"
    }
]

async def run_end_to_end_simulation():
    print("\n" + "="*80)
    print("🚀 ORBITWORKS MULTI-CHANNEL AI EMAIL AUTOMATION ENGINE - E2E SIMULATOR")
    print("="*80 + "\n")
    
    tenant_id = settings.DEFAULT_TENANT_ID
    results = []

    for idx, lead in enumerate(SIMULATED_LEADS, start=1):
        print(f"👉 [{idx}/4] Simulating Lead Ingestion via '{lead['channel']}'...")
        print(f"   Lead Email: {mask_email(lead['email'])} | Company: {lead['company_name']}")
        
        # 1. Process Lead Sequence (Step 1 Copywriting + Resend Dispatch)
        start_res = await process_new_lead_sequence(tenant_id, lead["channel"], lead)
        print(f"   ✅ Sequence Dispatch Status: {start_res['status']} | MessageID: {start_res.get('message_id')}")
        
        # 2. Simulate Resend Open Callback
        resend_open = {
            "type": "email.opened",
            "data": {"to": [lead["email"]]}
        }
        await handle_resend_webhook_event(tenant_id, resend_open)
        print(f"   📬 Telemetry Callback: Triggered 'email.opened' for {mask_email(lead['email'])}")

        results.append({
            "lead": lead["full_name"],
            "channel": lead["channel"],
            "dispatch_status": start_res["status"],
            "message_id": start_res.get("message_id")
        })
        print("-" * 60)

    # 3. Simulate Calendly Booking Event for Lead 1 to test auto sequence-pausing
    booked_lead = SIMULATED_LEADS[0]
    print(f"\n📅 Simulating Calendly Booking for {mask_email(booked_lead['email'])}...")
    calendly_payload = {
        "payload": {
            "email": booked_lead["email"],
            "event": "https://api.calendly.com/events/SIMULATED_BOOKING_99",
            "start_time": "2026-09-25T14:00:00Z"
        }
    }
    booking_res = await handle_calendly_booking_event(tenant_id, calendly_payload)
    print(f"   ✅ Auto-Pause Sequence Result: {booking_res['message']}\n")

    print("="*80)
    print("✨ END-TO-END MULTI-CHANNEL SIMULATION COMPLETED SUCCESSFULLY!")
    print("="*80 + "\n")

if __name__ == "__main__":
    asyncio.run(run_end_to_end_simulation())
