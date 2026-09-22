import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:
    from pydantic.v1 import BaseSettings
    SettingsConfigDict = dict


class Settings(BaseSettings):

    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    APP_SECRET_KEY: str = os.getenv("APP_SECRET_KEY", "default-dev-secret-key-32-characters-min")
    DEFAULT_TENANT_ID: str = os.getenv("DEFAULT_TENANT_ID", "00000000-0000-0000-0000-000000000001")
    PII_ENCRYPTION_KEY: str = os.getenv("PII_ENCRYPTION_KEY", "default-pii-encryption-key-32-bytes!")

    SUPABASE_URL: Optional[str] = os.getenv("SUPABASE_URL")
    SUPABASE_SERVICE_ROLE_KEY: Optional[str] = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    GROQ_API_KEY: Optional[str] = os.getenv("GROQ_API_KEY")
    LLM_TIMEOUT_SECONDS: float = float(os.getenv("LLM_TIMEOUT_SECONDS", "4.0"))

    RESEND_API_KEY: Optional[str] = os.getenv("RESEND_API_KEY")
    DEFAULT_SENDER_EMAIL: str = os.getenv("DEFAULT_SENDER_EMAIL", "outreach@orb-itworks.com")
    UNSUBSCRIBE_BASE_URL: str = os.getenv("UNSUBSCRIBE_BASE_URL", "https://app.orbitworks.ai/api/v1/unsubscribe")

    # Meta Webhook — two distinct values
    META_WEBHOOK_VERIFY_TOKEN: str = os.getenv("META_WEBHOOK_VERIFY_TOKEN", "meta_verify_secret_token")
    META_APP_SECRET: str = os.getenv("META_APP_SECRET", "meta_app_secret_key")

    CALENDLY_WEBHOOK_SECRET: str = os.getenv("CALENDLY_WEBHOOK_SECRET", "calendly_signing_secret_key")
    CALENDLY_SCHEDULING_URL: str = os.getenv("CALENDLY_SCHEDULING_URL", "https://calendly.com/hello-orb-itworks/30min")
    GOOGLE_ADS_LEAD_SECRET: str = os.getenv("GOOGLE_ADS_LEAD_SECRET", "google_ads_lead_secret_key")
    LINKEDIN_ADS_SECRET: str = os.getenv("LINKEDIN_ADS_SECRET", "linkedin_lead_secret_key")
    WEBSITE_WEBHOOK_SECRET: str = os.getenv("WEBSITE_WEBHOOK_SECRET", "website_webhook_secret_key")

    ALLOW_UNSIGNED_WEBHOOKS: bool = os.getenv("ALLOW_UNSIGNED_WEBHOOKS", "false").lower() == "true"

    GA4_MEASUREMENT_ID: Optional[str] = os.getenv("GA4_MEASUREMENT_ID")
    GA4_API_SECRET: Optional[str] = os.getenv("GA4_API_SECRET")

    # Human-in-the-loop approval gate
    REQUIRE_EMAIL_APPROVAL: bool = os.getenv("REQUIRE_EMAIL_APPROVAL", "false").lower() == "true"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    def _validate_production_config(self) -> None:
        if self.ENVIRONMENT == "production":
            problems = []
            if self.ALLOW_UNSIGNED_WEBHOOKS:
                problems.append("ALLOW_UNSIGNED_WEBHOOKS=True is strictly forbidden in production mode.")
            if self.APP_SECRET_KEY == "default-dev-secret-key-32-characters-min":
                problems.append("Default APP_SECRET_KEY cannot be used in production mode.")
            if not self.RESEND_API_KEY or "your_resend" in self.RESEND_API_KEY:
                problems.append("RESEND_API_KEY is not configured for production.")
            if not self.META_APP_SECRET or self.META_APP_SECRET == "meta_app_secret_key":
                problems.append("META_APP_SECRET is not configured for production.")
            if problems:
                raise ValueError("Invalid production config:\n" + "\n".join(f"- {p}" for p in problems))


settings = Settings()
settings._validate_production_config()


