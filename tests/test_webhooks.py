try:
    import pytest
except ImportError:
    pytest = None
from fastapi.testclient import TestClient
from ai_email_engine.main import app
from ai_email_engine.config import settings

client = TestClient(app)

def test_meta_webhook_challenge_verification():
    response = client.get(
        "/api/v1/webhooks/meta-ads",
        params={
            "hub.mode": "subscribe",
            "hub.challenge": "12345678",
            "hub.verify_token": settings.META_WEBHOOK_VERIFY_TOKEN
        }
    )
    assert response.status_code == 200
    assert response.text == "12345678"

import hmac, hashlib, json

def test_unsigned_webhook_rejected():
    payload = {"full_name": "Unsigned Attacker", "email": "hacker@domain.com"}
    response = client.post("/api/v1/webhooks/website", json=payload)
    assert response.status_code == 401, f"Expected 401 Unauthorized for unsigned webhook, got {response.status_code}"

def test_website_webhook_ingestion():
    payload = {
        "full_name": "Test User",
        "email": "testuser@orbitworks.ai",
        "company_name": "Acme Corp",
        "notes": "Looking for lead automation"
    }
    raw_body = json.dumps(payload).encode("utf-8")
    sig = hmac.new(settings.WEBSITE_WEBHOOK_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    response = client.post(
        "/api/v1/webhooks/website",
        content=raw_body,
        headers={"Content-Type": "application/json", "X-Webhook-Signature": f"sha256={sig}"}
    )
    assert response.status_code == 202, f"Expected 202 Accepted, got {response.status_code}"
    data = response.json()
    assert data["status"] == "accepted"



def test_provider_payload_normalization_shapes():
    from ai_email_engine.api.webhooks import extract_provider_lead_payload

    # 1. Meta Ads nested shape
    meta_raw = {
        "entry": [{
            "changes": [{
                "value": {
                    "leadgen_id": "meta_lead_123",
                    "field_data": [
                        {"name": "email", "values": ["meta@acme.com"]},
                        {"name": "full_name", "values": ["Meta User"]},
                        {"name": "company_name", "values": ["Meta Corp"]}
                    ]
                }
            }]
        }]
    }
    meta_norm = extract_provider_lead_payload("meta_ads", meta_raw)
    assert meta_norm["lead_id"] == "meta_lead_123"
    assert meta_norm["email"] == "meta@acme.com"
    assert meta_norm["full_name"] == "Meta User"

    # 2. LinkedIn inline form answers shape
    linkedin_inline = {
        "lead_id": "li_lead_456",
        "formResponse": {
            "answers": [
                {"fieldId": "email", "values": ["li@acme.com"]},
                {"fieldId": "full_name", "values": ["LinkedIn User"]},
                {"fieldId": "company_name", "values": ["LinkedIn Corp"]}
            ]
        }
    }
    li_norm = extract_provider_lead_payload("linkedin_ads", linkedin_inline)
    assert li_norm["lead_id"] == "li_lead_456"
    assert li_norm["email"] == "li@acme.com"

    # 3. LinkedIn ID-only shape
    linkedin_id_only = {"leadgen_id": "li_lead_789", "formId": "form_99"}
    li_id_norm = extract_provider_lead_payload("linkedin_ads", linkedin_id_only)
    assert li_id_norm["lead_id"] == "li_lead_789"
    assert li_id_norm["requires_api_fetch"] is True

    # 4. Google Ads user_column_data shape
    google_raw = {
        "gclid": "google_click_id_000",
        "user_column_data": [
            {"column_name": "EMAIL", "string_value": "google@acme.com"},
            {"column_name": "FULL_NAME", "string_value": "Google User"},
            {"column_name": "COMPANY_NAME", "string_value": "Google Corp"}
        ]
    }
    g_norm = extract_provider_lead_payload("google_ads", google_raw)
    assert g_norm["gclid"] == "google_click_id_000"
    assert g_norm["email"] == "google@acme.com"


def test_pydantic_schema_validation_rejection():
    from unittest.mock import patch
    with patch.object(settings, "ALLOW_UNSIGNED_WEBHOOKS", True):
        # 1. Invalid website payload (missing required email field)
        invalid_payload = {"company_name": "No Email Corp"}
        raw_body = json.dumps(invalid_payload).encode("utf-8")
        response = client.post(
            "/api/v1/webhooks/website",
            content=raw_body,
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422, f"Expected 422 Unprocessable Entity, got {response.status_code}"

        # 2. Garbage Meta Ads payload (missing required email and full_name)
        garbage_meta = {"junk_field": "whatever"}
        raw_meta = json.dumps(garbage_meta).encode("utf-8")
        res_meta = client.post(
            "/api/v1/webhooks/meta-ads",
            content=raw_meta,
            headers={"Content-Type": "application/json"}
        )
        assert res_meta.status_code == 422, f"Expected 422 Unprocessable Entity for meta_ads, got {res_meta.status_code}"

        # 3. Garbage Google Ads payload
        garbage_google = {"invalid": True}
        raw_google = json.dumps(garbage_google).encode("utf-8")
        res_google = client.post(
            "/api/v1/webhooks/google-ads",
            content=raw_google,
            headers={"Content-Type": "application/json"}
        )
        assert res_google.status_code == 422, f"Expected 422 Unprocessable Entity for google_ads, got {res_google.status_code}"


if __name__ == "__main__":
    import sys
    tests = [
        test_meta_webhook_challenge_verification,
        test_unsigned_webhook_rejected,
        test_website_webhook_ingestion,
        test_provider_payload_normalization_shapes,
        test_pydantic_schema_validation_rejection,
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
    print(f"\n{passed}/{passed + failed} webhook tests passed")
    sys.exit(0 if failed == 0 else 1)

