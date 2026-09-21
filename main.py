import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI

from fastapi.responses import JSONResponse

from ai_email_engine.config import settings
from ai_email_engine.security.rls_middleware import RequestIDMiddleware
from ai_email_engine.api import webhooks
from ai_email_engine.api import compliance
from ai_email_engine.workers.job_runner import recover_unprocessed_webhooks
from ai_email_engine.workers.sequence_scheduler import run_sequence_scheduler_loop
from ai_email_engine.services.alerting import alert_critical

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ai_email_engine")


def _validate_production_config() -> None:
    """Startup config validation."""
    if settings.ENVIRONMENT != "production":
        return

    problems = []
    if not settings.RESEND_API_KEY or "your_resend" in settings.RESEND_API_KEY:
        problems.append("RESEND_API_KEY is not set — all emails will be silently lost")
    if not settings.OPENAI_API_KEY or "your-openai" in settings.OPENAI_API_KEY:
        problems.append("OPENAI_API_KEY is not set — LLM copy generation disabled")
    if not settings.META_APP_SECRET or settings.META_APP_SECRET == "meta_app_secret_key":
        problems.append("META_APP_SECRET is at default — Meta webhook signatures will all fail")
    if not settings.SUPABASE_URL:
        problems.append("SUPABASE_URL is not set — running on in-memory mock DB")

    for problem in problems:
        alert_critical("startup_config_invalid", problem)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan context manager for startup and shutdown events."""
    _validate_production_config()
    logger.info("OrbitWorks Email Engine v3.0.0 starting up...")
    await recover_unprocessed_webhooks()
    scheduler_task = asyncio.create_task(run_sequence_scheduler_loop(poll_interval_seconds=60))
    logger.info("Sequence scheduler started — polling every 60s for due email steps")
    yield
    scheduler_task.cancel()
    logger.info("OrbitWorks Email Engine shutting down...")


app = FastAPI(
    title="OrbitWorks Multi-Channel AI Email Automation Engine",
    description="Production-grade AI email personalization, webhook ingestion, sequence scheduling, and GA4 telemetry.",
    version="3.0.0",
    lifespan=lifespan,
)

app.add_middleware(RequestIDMiddleware)
app.include_router(webhooks.router)
app.include_router(compliance.router)



@app.get("/")
async def root():
    return {
        "engine": "OrbitWorks Multi-Channel AI Email Automation Engine",
        "version": "3.0.0",
        "status": "operational",
        "environment": settings.ENVIRONMENT,
    }


@app.get("/health")
async def health_check():
    """
    Issue 11 fix — real health check that verifies DB connectivity and config presence.
    Previously returned hardcoded "connected" regardless of actual state.
    """
    from ai_email_engine.database.connection import get_db_client

    db_status = "unknown"
    db_is_mock = False
    try:
        db = get_db_client()
        db_is_mock = hasattr(db, "tables")  # MockSupabaseClient has .tables attr
        if not db_is_mock:
            # Real Supabase ping — attempt a lightweight query
            db.table("webhook_events").select("id").execute()
            db_status = "connected"
        else:
            db_status = "mock (dev mode)"
    except Exception as e:
        db_status = f"error: {e}"

    config_warnings = []
    if not settings.RESEND_API_KEY:
        config_warnings.append("RESEND_API_KEY missing — emails are mock dispatches")
    if not settings.OPENAI_API_KEY:
        config_warnings.append("OPENAI_API_KEY missing — using fallback templates")
    if not settings.GROQ_API_KEY:
        config_warnings.append("GROQ_API_KEY missing — Groq extraction disabled")

    return JSONResponse(
        status_code=200 if "error" not in db_status else 503,
        content={
            "status": "healthy" if "error" not in db_status else "degraded",
            "environment": settings.ENVIRONMENT,
            "database": db_status,
            "config_warnings": config_warnings,
            "sequence_scheduler": "running",
        },
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ai_email_engine.main:app", host="0.0.0.0", port=8000, reload=True)
