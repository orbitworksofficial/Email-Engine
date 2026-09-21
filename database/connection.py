import logging
from typing import Optional, Dict, Any, List, Set, Tuple
from ai_email_engine.config import settings

logger = logging.getLogger("ai_email_engine.database")

try:
    from supabase import create_client, Client
    HAS_SUPABASE = True
except ImportError:
    HAS_SUPABASE = False


# UNIQUE constraint definitions per table.
# Format: table_name -> list of column-tuples that must be unique together.
_UNIQUE_CONSTRAINTS: Dict[str, List[Tuple[str, ...]]] = {
    "webhook_events": [("tenant_id", "payload_hash")],
    "suppression_list": [("tenant_id", "email")],
    "email_campaign_states": [("tenant_id", "lead_id")],
    "email_logs": [("tenant_id", "campaign_state_id", "step_number")],
    "email_drafts": [("tenant_id", "campaign_state_id", "step_number")],
    "tenant_api_keys": [("api_key_hash",)],
    "rate_limit_counters": [("tenant_id", "endpoint", "window_start")],
}



class UniqueViolationError(Exception):
    """Raised when an INSERT would violate a UNIQUE constraint in MockSupabaseClient."""
    pass


class MockSupabaseClient:
    """
    In-memory mock database client for testing and isolated development.
    Enforces UNIQUE constraints on INSERT, raising UniqueViolationError.
    Supports rpc() calls for testing session context setting.

    Note on Multi-tenancy Architecture:
    Explicit `.eq("tenant_id", tenant_id)` filters on all database queries serve as the primary
    multi-tenant isolation boundary across stateless PostgREST HTTP calls, supplemented by
    `set_tenant_session_context()` GUC setting for Postgres RLS defense-in-depth.
    """
    def __init__(self):
        self.tables: Dict[str, List[Dict[str, Any]]] = {
            "webhook_events": [],
            "suppression_list": [],
            "email_campaign_states": [],
            "email_logs": [],
            "email_drafts": [],
            "tenant_api_keys": [],
            "rate_limit_counters": [],
        }
        self.session_config: Dict[str, Any] = {}

    def table(self, name: str):
        return MockTableQuery(self.tables.setdefault(name, []), name)

    def rpc(self, fn_name: str, params: Optional[Dict[str, Any]] = None):
        if fn_name == "set_config" and params:
            setting = params.get("setting")
            value = params.get("value")
            if setting:
                self.session_config[setting] = value
        return MockExecuteResult([])


class MockTableQuery:
    def __init__(self, data: List[Dict[str, Any]], table_name: str = ""):
        self.data = data
        self.table_name = table_name
        self.filters: List[Tuple[str, Any]] = []
        self._update_values: Optional[Dict[str, Any]] = None
        self._mode: str = "select"  # "select" or "update"


    def insert(self, record: Dict[str, Any]):
        records = record if isinstance(record, list) else [record]
        constraints = _UNIQUE_CONSTRAINTS.get(self.table_name, [])
        for rec in records:
            for constraint_cols in constraints:
                # Check if any existing row violates the unique constraint
                for existing in self.data:
                    if all(
                        existing.get(col) is not None and existing.get(col) == rec.get(col)
                        for col in constraint_cols
                    ):
                        raise UniqueViolationError(
                            f"duplicate key value violates unique constraint on "
                            f"{self.table_name}({', '.join(constraint_cols)}): "
                            f"23505"
                        )
            self.data.append(rec)
        return self

    def select(self, *args, **kwargs):
        return self

    def eq(self, column: str, value: Any):
        self.filters.append((column, value))
        return self

    def update(self, values: Dict[str, Any]):
        # Store values only — actual update applied in execute() after eq() filters are set
        self._update_values = values
        self._mode = "update"
        return self


    def execute(self):
        result = []
        for row in self.data:
            match = all(row.get(col) == val for col, val in self.filters)
            if match:
                if getattr(self, "_mode", None) == "update" and self._update_values:
                    row.update(self._update_values)
                result.append(row)
        if getattr(self, "_mode", None) == "update":
            return MockExecuteResult(result)
        return MockExecuteResult(result if self.filters else list(self.data))



class MockExecuteResult:
    def __init__(self, data: List[Dict[str, Any]]):
        self.data = data


_db_client: Optional[Any] = None


def get_db_client() -> Any:
    global _db_client
    if _db_client is not None:
        return _db_client

    if HAS_SUPABASE and settings.SUPABASE_URL and settings.SUPABASE_SERVICE_ROLE_KEY:
        try:
            _db_client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)
            logger.info("Initialized live Supabase DB client.")
            return _db_client
        except Exception as e:
            logger.warning(f"Failed to connect to Supabase: {e}. Falling back to mock DB client.")

    _db_client = MockSupabaseClient()
    logger.info("Initialized Mock DB client.")
    return _db_client


def set_tenant_session_context(db: Any, tenant_id: str) -> None:
    """
    Sets Postgres session setting `app.current_tenant_id` for RLS policy evaluation.
    Used when executing operations under user/tenant context rather than service_role bypass.
    """
    if not tenant_id:
        return
    try:
        if hasattr(db, "rpc"):
            db.rpc("set_config", {"setting": "app.current_tenant_id", "value": tenant_id, "is_local": True}).execute()
        elif hasattr(db, "tenant_id"):
            db.tenant_id = tenant_id
    except Exception as e:
        logger.debug(f"Could not set tenant session context (proceeding with query-level tenant filtering): {e}")


def reset_db_client() -> None:
    """Resets the singleton DB client. Use in tests to get a fresh mock per test."""
    global _db_client
    _db_client = None
