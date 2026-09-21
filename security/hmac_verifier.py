import hmac
import hashlib
from typing import Optional


def verify_hmac_sha256(payload: bytes, signature: str, secret: str) -> bool:
    """
    Verifies HMAC-SHA256 signature using constant-time string comparison.
    Accepts signatures with or without a 'sha256=' prefix.
    """
    if not signature or not secret:
        return False
    clean_signature = signature.replace("sha256=", "").strip()
    expected_mac = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_mac.lower(), clean_signature.lower())


def verify_meta_signature(raw_body: bytes, signature_header: Optional[str], app_secret: str) -> bool:
    """
    Verifies Meta Ads POST webhook payload signature via X-Hub-Signature-256 header.
    IMPORTANT: app_secret here must be META_APP_SECRET (App Dashboard → Settings → Basic),
    NOT META_WEBHOOK_VERIFY_TOKEN which is only used in the GET handshake.
    """
    if not signature_header:
        return False
    return verify_hmac_sha256(raw_body, signature_header, app_secret)


def verify_calendly_signature(
    raw_body: bytes,
    signature_header: Optional[str],
    webhook_secret: str,
    timestamp_tolerance_sec: int = 300
) -> bool:
    """
    Verifies Calendly webhook signature from X-Calendly-Hook-Signature header.
    Format: t=<unix_timestamp>,v1=<hex_signature>
    The signed string is: "<timestamp>.<raw_body>"
    """
    if not signature_header:
        return False
    parts = dict(item.split("=", 1) for item in signature_header.split(",") if "=" in item)
    t = parts.get("t")
    v1 = parts.get("v1")
    if not t or not v1:
        return False
    signed_payload = f"{t}.{raw_body.decode('utf-8')}".encode('utf-8')
    return verify_hmac_sha256(signed_payload, v1, webhook_secret)


def verify_google_lead_secret(header_secret: Optional[str], expected_secret: str) -> bool:
    """Verifies Google Lead Form X-Google-Lead-Secret header using constant-time comparison."""
    if not header_secret or not expected_secret:
        return False
    return hmac.compare_digest(header_secret.strip(), expected_secret.strip())


def verify_linkedin_signature(raw_body: bytes, signature_header: Optional[str], secret: str) -> bool:
    """
    Verifies LinkedIn Lead Gen webhook HMAC-SHA256 signature.
    LinkedIn sends X-LI-Signature: sha256=<hex> (same pattern as Meta).
    """
    if not signature_header:
        return False
    return verify_hmac_sha256(raw_body, signature_header, secret)


def verify_website_signature(raw_body: bytes, signature_header: Optional[str], secret: str) -> bool:
    """
    Verifies internal website form webhook HMAC-SHA256 signature.
    Header: X-Webhook-Signature: sha256=<hex>
    """
    if not signature_header:
        return False
    return verify_hmac_sha256(raw_body, signature_header, secret)
