import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from ai_email_engine.config import settings
from ai_email_engine.database.connection import get_db_client

logger = logging.getLogger("ai_email_engine.security.rate_limiter")

DEFAULT_WINDOW_MINUTES = 10
DEFAULT_MAX_REQUESTS = 100


def is_rate_limited(
    tenant_id: str,
    endpoint: str,
    max_requests: int = DEFAULT_MAX_REQUESTS,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> bool:
    """
    Sliding window rate limiter backed by rate_limit_counters table.
    Sums request counts across all active discrete buckets within the rolling time window.
    Returns True if total requests >= max_requests.

    In production, database connection errors fail closed (return True) to prevent unthrottled abuse during DB degradation.
    In development/testing, errors fail open (return False) with a warning.
    """
    try:
        db = get_db_client()
        now = datetime.now(timezone.utc)
        window_start = now.replace(
            minute=(now.minute // window_minutes) * window_minutes,
            second=0,
            microsecond=0,
        ).isoformat()

        # Step 1: Ensure current window row exists (insert-first pattern)
        try:
            db.table("rate_limit_counters").insert({
                "id": str(uuid.uuid4()),
                "tenant_id": tenant_id,
                "endpoint": endpoint,
                "window_start": window_start,
                "count": 1,
            }).execute()
            inserted_fresh = True
        except Exception as insert_exc:
            err = str(insert_exc).lower()
            if "unique" not in err and "23505" not in err and "duplicate" not in err:
                logger.warning(f"Rate limiter non-unique insert error: {insert_exc}")
                if settings.ENVIRONMENT == "production":
                    return True
                return False
            inserted_fresh = False

        # Step 2: Sum count across all buckets within rolling threshold
        threshold_time = (now - timedelta(minutes=window_minutes)).isoformat()
        res = (
            db.table("rate_limit_counters")
            .select("id, window_start, count")
            .eq("tenant_id", tenant_id)
            .eq("endpoint", endpoint)
            .execute()
        )
        if not res or not res.data:
            if settings.ENVIRONMENT == "production":
                return True
            return False

        matching_rows = [r for r in res.data if r.get("window_start", "") >= threshold_time]
        total_requests = sum(r.get("count", 0) for r in matching_rows)

        if total_requests >= max_requests:
            logger.warning(
                f"[RATE LIMIT] Tenant {tenant_id[:8]} hit limit on '{endpoint}' "
                f"({total_requests}/{max_requests} in {window_minutes}m sliding window)"
            )
            return True

        if not inserted_fresh:
            current_row = next((r for r in res.data if r.get("window_start") == window_start), None)
            if current_row:
                db.table("rate_limit_counters").update(
                    {"count": current_row.get("count", 0) + 1}
                ).eq("id", current_row["id"]).execute()

        return False

    except Exception as e:
        logger.warning(f"Rate limiter read/update error: {e}")
        if settings.ENVIRONMENT == "production":
            return True
        return False
