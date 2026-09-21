import base64
import hashlib
import hmac
import re
from typing import Optional
from cryptography.fernet import Fernet

from ai_email_engine.config import settings

def _derive_keys(raw_key: str):
    hmac_key = hashlib.sha256((raw_key + ":hmac").encode('utf-8')).digest()
    fernet_raw = hashlib.sha256((raw_key + ":fernet").encode('utf-8')).digest()
    fernet_key = base64.urlsafe_b64encode(fernet_raw)
    return hmac_key, fernet_key

_HMAC_KEY, _FERNET_KEY = _derive_keys(settings.PII_ENCRYPTION_KEY)
_fernet = Fernet(_FERNET_KEY)

def encrypt_pii(data: str) -> str:
    """Encrypts sensitive PII string using AES-256 (Fernet).
    NOTE: Fernet produces a non-deterministic ciphertext (random IV each time).
    Use hash_pii_for_lookup() when you need a consistent lookup key."""
    if not data:
        return data
    encrypted = _fernet.encrypt(data.encode('utf-8'))
    return encrypted.decode('utf-8')


def hash_pii_for_lookup(data: str) -> str:
    """
    Creates a deterministic HMAC-SHA256 keyed hash of a PII value for DB lookups.
    Use this for suppression list and dedup checks instead of encrypt_pii().
    The hash is keyed on PII_ENCRYPTION_KEY (derived HMAC subkey) so it cannot be reversed.
    """
    if not data:
        return ""
    return hmac.new(
        _HMAC_KEY,
        data.lower().strip().encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

def decrypt_pii(encrypted_data: str) -> str:
    """Decrypts sensitive PII string. Raises ValueError if decryption fails."""
    if not encrypted_data:
        return encrypted_data
    try:
        decrypted = _fernet.decrypt(encrypted_data.encode('utf-8'))
        return decrypted.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Failed to decrypt PII data: {e}") from e

def mask_email(email: Optional[str]) -> str:
    """Masks email address for secure logging (e.g. j***n@company.com)."""
    if not email or "@" not in email:
        return "***@***.com"
    username, domain = email.split("@", 1)
    if len(username) <= 2:
        masked_user = username[0] + "*"
    else:
        masked_user = username[0] + "*" * (len(username) - 2) + username[-1]
    return f"{masked_user}@{domain}"

def sanitize_input_string(text: Optional[str]) -> str:
    """
    Sanitizes untrusted input text to protect against prompt injection vectors.
    Strips system prompt control tags, curly braces, and markdown code injections.
    """
    if not text:
        return ""
    sanitized = re.sub(r'<\/?(system|user|assistant|prompt|instructions)[^>]*>', '', text, flags=re.IGNORECASE)
    sanitized = sanitized.replace("{", "(").replace("}", ")")
    return sanitized.strip()[:2000]
