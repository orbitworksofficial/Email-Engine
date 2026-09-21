import base64
import hashlib
import hmac
import logging
import time
from typing import Optional, Tuple

from ai_email_engine.config import settings
from ai_email_engine.security.pii_crypto import hash_pii_for_lookup

logger = logging.getLogger('ai_email_engine.security.unsubscribe_tokens')

def generate_unsubscribe_token(tenant_id: str, email: str, timestamp: Optional[int] = None) -> str:
    """Generates a signed, tamper-proof unsubscribe token containing tenant_id, email_hash, and timestamp."""
    ts = timestamp or int(time.time())
    email_hash = hash_pii_for_lookup(email)
    msg = f'{tenant_id}:{email_hash}:{ts}'
    sig = hmac.new(settings.APP_SECRET_KEY.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()[:32]
    payload = f'{tenant_id}.{email_hash}.{ts}.{sig}'
    return base64.urlsafe_b64encode(payload.encode('utf-8')).decode('utf-8').rstrip('=')

def verify_unsubscribe_token(token: str, max_age_seconds: int = 30 * 86400) -> Optional[Tuple[str, str]]:
    """
    Verifies a signed unsubscribe token.
    Returns (tenant_id, email_hash) if valid and not expired, None otherwise.
    """
    if not token:
        return None
    try:
        padding = '=' * (-len(token) % 4)
        decoded = base64.urlsafe_b64decode((token + padding).encode('utf-8')).decode('utf-8')
        parts = decoded.split('.')
        if len(parts) != 4:
            return None
        tenant_id, email_hash, ts_str, sig = parts
        ts = int(ts_str)

        if abs(int(time.time()) - ts) > max_age_seconds:
            logger.warning('[UNSUBSCRIBE] Token expired')
            return None

        msg = f'{tenant_id}:{email_hash}:{ts}'
        expected_sig = hmac.new(settings.APP_SECRET_KEY.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()[:32]
        if hmac.compare_digest(sig, expected_sig):
            return tenant_id, email_hash
    except Exception as e:
        logger.warning(f'[UNSUBSCRIBE] Token verification error: {e}')
    return None
