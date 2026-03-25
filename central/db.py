"""SQLite persistence for tenants, firewalls, and licenses with upsert support."""

from __future__ import annotations

import contextvars
import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SYNC_META_COLUMNS = frozenset({"first_sync", "last_sync", "sync_id", "client_id"})

# (sync_id, client_id, run_timestamp) when set by :func:`sync_change_logging`.
_sync_change_ctx: contextvars.ContextVar[Optional[tuple[str, str, str]]] = (
    contextvars.ContextVar("sync_change_ctx", default=None)
)


@contextmanager
def sync_change_logging(sync_id: str, client_id: str, run_timestamp: str):
    """Enable per-row change logging into ``sync_change_events`` for this sync run."""
    token = _sync_change_ctx.set((sync_id, client_id, run_timestamp))
    try:
        yield
    finally:
        _sync_change_ctx.reset(token)

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path("sophos_central.db")


def _json_serial(obj: Any) -> Any:
    if hasattr(obj, "id"):
        return obj.id
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def _to_json(obj: Any) -> Optional[str]:
    if obj is None:
        return None
    try:
        return json.dumps(obj, default=_json_serial)
    except Exception:
        return json.dumps(str(obj))


def _get(obj: Any, attr: str, default: Any = None) -> Any:
    """Get attribute from an object or key from a dict."""
    if isinstance(obj, dict):
        return obj[attr] if attr in obj else default
    if hasattr(obj, attr):
        return getattr(obj, attr)
    return default


def _get_nested(obj: Any, *keys: str, default: Any = None) -> Any:
    """Get nested attribute or key. e.g. _get_nested(tenant, 'partner', 'id')."""
    for k in keys:
        obj = _get(obj, k, None)
        if obj is None:
            return default
    return obj


def get_new_alert_ids(
    conn: sqlite3.Connection, sync_id: str, tenant_id: str
) -> list[str]:
    """Return alert IDs that were added (first_sync = last_sync) in this run for the given tenant."""
    cur = conn.execute(
        "SELECT id FROM alerts WHERE sync_id = ? AND first_sync = last_sync AND tenant_id = ?",
        (sync_id, tenant_id),
    )
    return [row[0] for row in cur.fetchall()]


# Pre-built queries for get_run_summary (table names are fixed; no user input).
_RUN_SUMMARY_TABLES = (
    "tenants",
    "firewalls",
    "licenses",
    "license_subscriptions",
    "alerts",
    "alert_details",
    "firmware_upgrades",
    "firmware_versions",
    "firewall_groups",
    "firewall_group_sync_status",
    "mdr_threat_feed_sync",
    "tenant_roles",
    "tenant_admins",
)
_RUN_SUMMARY_QUERIES = {
    "tenants": (
        "SELECT COUNT(*) FROM tenants WHERE sync_id = ? AND first_sync = last_sync",
        "SELECT COUNT(*) FROM tenants WHERE sync_id = ? AND (first_sync IS NULL OR first_sync != last_sync)",
    ),
    "firewalls": (
        "SELECT COUNT(*) FROM firewalls WHERE sync_id = ? AND first_sync = last_sync",
        "SELECT COUNT(*) FROM firewalls WHERE sync_id = ? AND (first_sync IS NULL OR first_sync != last_sync)",
    ),
    "licenses": (
        "SELECT COUNT(*) FROM licenses WHERE sync_id = ? AND first_sync = last_sync",
        "SELECT COUNT(*) FROM licenses WHERE sync_id = ? AND (first_sync IS NULL OR first_sync != last_sync)",
    ),
    "license_subscriptions": (
        "SELECT COUNT(*) FROM license_subscriptions WHERE sync_id = ? AND first_sync = last_sync",
        "SELECT COUNT(*) FROM license_subscriptions WHERE sync_id = ? AND (first_sync IS NULL OR first_sync != last_sync)",
    ),
    "alerts": (
        "SELECT COUNT(*) FROM alerts WHERE sync_id = ? AND first_sync = last_sync",
        "SELECT COUNT(*) FROM alerts WHERE sync_id = ? AND (first_sync IS NULL OR first_sync != last_sync)",
    ),
    "alert_details": (
        "SELECT COUNT(*) FROM alert_details WHERE sync_id = ? AND first_sync = last_sync",
        "SELECT COUNT(*) FROM alert_details WHERE sync_id = ? AND (first_sync IS NULL OR first_sync != last_sync)",
    ),
    "firmware_upgrades": (
        "SELECT COUNT(*) FROM firmware_upgrades WHERE sync_id = ? AND first_sync = last_sync",
        "SELECT COUNT(*) FROM firmware_upgrades WHERE sync_id = ? AND (first_sync IS NULL OR first_sync != last_sync)",
    ),
    "firmware_versions": (
        "SELECT COUNT(*) FROM firmware_versions WHERE sync_id = ? AND first_sync = last_sync",
        "SELECT COUNT(*) FROM firmware_versions WHERE sync_id = ? AND (first_sync IS NULL OR first_sync != last_sync)",
    ),
    "firewall_groups": (
        "SELECT COUNT(*) FROM firewall_groups WHERE sync_id = ? AND first_sync = last_sync",
        "SELECT COUNT(*) FROM firewall_groups WHERE sync_id = ? AND (first_sync IS NULL OR first_sync != last_sync)",
    ),
    "firewall_group_sync_status": (
        "SELECT COUNT(*) FROM firewall_group_sync_status WHERE sync_id = ? AND first_sync = last_sync",
        "SELECT COUNT(*) FROM firewall_group_sync_status WHERE sync_id = ? AND (first_sync IS NULL OR first_sync != last_sync)",
    ),
    "mdr_threat_feed_sync": (
        "SELECT COUNT(*) FROM mdr_threat_feed_sync WHERE sync_id = ? AND first_sync = last_sync",
        "SELECT COUNT(*) FROM mdr_threat_feed_sync WHERE sync_id = ? AND (first_sync IS NULL OR first_sync != last_sync)",
    ),
    "tenant_roles": (
        "SELECT COUNT(*) FROM tenant_roles WHERE sync_id = ? AND first_sync = last_sync",
        "SELECT COUNT(*) FROM tenant_roles WHERE sync_id = ? AND (first_sync IS NULL OR first_sync != last_sync)",
    ),
    "tenant_admins": (
        "SELECT COUNT(*) FROM tenant_admins WHERE sync_id = ? AND first_sync = last_sync",
        "SELECT COUNT(*) FROM tenant_admins WHERE sync_id = ? AND (first_sync IS NULL OR first_sync != last_sync)",
    ),
}


def get_run_summary(conn: sqlite3.Connection, sync_id: str) -> dict[str, dict[str, int]]:
    """Return per-table counts of records added and updated in the run with the given sync_id."""
    summary: dict[str, dict[str, int]] = {}
    for table in _RUN_SUMMARY_TABLES:
        added_sql, updated_sql = _RUN_SUMMARY_QUERIES[table]
        added_cur = conn.execute(added_sql, (sync_id,))
        updated_cur = conn.execute(updated_sql, (sync_id,))
        summary[table] = {
            "added": added_cur.fetchone()[0],
            "updated": updated_cur.fetchone()[0],
        }
    return summary


def get_connection(db_path: Path | str) -> sqlite3.Connection:
    path = Path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def get_latest_alert_raised_at(
    conn: sqlite3.Connection, tenant_id: str
) -> Optional[str]:
    """Return the latest raised_at (ISO 8601) for alerts for the given tenant, or None."""
    cur = conn.execute(
        "SELECT MAX(raised_at) FROM alerts WHERE tenant_id = ?",
        (tenant_id,),
    )
    row = cur.fetchone()
    if row and row[0] is not None:
        return str(row[0])
    return None


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY,
            show_as TEXT,
            name TEXT NOT NULL,
            data_geography TEXT,
            data_region TEXT,
            billing_type TEXT,
            partner_id TEXT,
            organization_id TEXT,
            api_host TEXT,
            status TEXT,
            contact_json TEXT,
            external_ids_json TEXT,
            products_json TEXT,
            updated_at TEXT NOT NULL,
            first_sync TEXT,
            last_sync TEXT,
            sync_id TEXT,
            client_id TEXT
        );

        CREATE TABLE IF NOT EXISTS firewalls (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            serial_number TEXT NOT NULL,
            group_id TEXT,
            group_name TEXT,
            hostname TEXT,
            name TEXT,
            external_ipv4_addresses_json TEXT,
            firmware_version TEXT,
            model TEXT,
            managing_status TEXT,
            reporting_status TEXT,
            connected INTEGER NOT NULL DEFAULT 0,
            suspended INTEGER NOT NULL DEFAULT 0,
            state_changed_at TEXT,
            capabilities_json TEXT,
            geo_latitude TEXT,
            geo_longitude TEXT,
            created_at TEXT,
            updated_at TEXT,
            first_sync TEXT,
            last_sync TEXT,
            sync_id TEXT,
            client_id TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );
        CREATE INDEX IF NOT EXISTS ix_firewalls_tenant_id ON firewalls(tenant_id);
        CREATE INDEX IF NOT EXISTS ix_firewalls_serial_number ON firewalls(serial_number);

        CREATE TABLE IF NOT EXISTS licenses (
            serial_number TEXT PRIMARY KEY,
            tenant_id TEXT,
            partner_id TEXT,
            organization_id TEXT,
            model TEXT,
            model_type TEXT,
            last_seen_at TEXT,
            first_sync TEXT,
            last_sync TEXT,
            sync_id TEXT,
            client_id TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );
        CREATE INDEX IF NOT EXISTS ix_licenses_tenant_id ON licenses(tenant_id);

        CREATE TABLE IF NOT EXISTS license_subscriptions (
            id TEXT NOT NULL,
            serial_number TEXT NOT NULL,
            license_identifier TEXT,
            product_code TEXT,
            product_name TEXT,
            start_date TEXT,
            end_date TEXT,
            perpetual INTEGER NOT NULL DEFAULT 0,
            type TEXT,
            quantity INTEGER,
            usage_count INTEGER,
            usage_date TEXT,
            unlimited INTEGER NOT NULL DEFAULT 0,
            first_sync TEXT,
            last_sync TEXT,
            sync_id TEXT,
            client_id TEXT,
            PRIMARY KEY (id),
            FOREIGN KEY (serial_number) REFERENCES licenses(serial_number)
        );
        CREATE INDEX IF NOT EXISTS ix_license_subscriptions_serial ON license_subscriptions(serial_number);

        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            tenant_id TEXT,
            category TEXT,
            description TEXT,
            group_key TEXT,
            product TEXT,
            raised_at TEXT,
            severity TEXT,
            type TEXT,
            allowed_actions_json TEXT,
            managed_agent_json TEXT,
            person_json TEXT,
            tenant_ref_json TEXT,
            first_sync TEXT,
            last_sync TEXT,
            sync_id TEXT,
            client_id TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_alerts_tenant_id ON alerts(tenant_id);
        CREATE INDEX IF NOT EXISTS ix_alerts_raised_at ON alerts(raised_at);

        CREATE TABLE IF NOT EXISTS alert_details (
            id TEXT PRIMARY KEY,
            tenant_id TEXT,
            category TEXT,
            description TEXT,
            group_key TEXT,
            product TEXT,
            raised_at TEXT,
            severity TEXT,
            type TEXT,
            allowed_actions_json TEXT,
            managed_agent_json TEXT,
            person_json TEXT,
            tenant_ref_json TEXT,
            first_sync TEXT,
            last_sync TEXT,
            sync_id TEXT,
            client_id TEXT,
            FOREIGN KEY (id) REFERENCES alerts(id)
        );
        CREATE INDEX IF NOT EXISTS ix_alert_details_tenant_id ON alert_details(tenant_id);

        CREATE TABLE IF NOT EXISTS firmware_upgrades (
            firewall_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            serial_number TEXT NOT NULL,
            current_version TEXT,
            upgrade_to_versions_json TEXT,
            first_sync TEXT,
            last_sync TEXT,
            sync_id TEXT,
            client_id TEXT,
            FOREIGN KEY (firewall_id) REFERENCES firewalls(id)
        );
        CREATE INDEX IF NOT EXISTS ix_firmware_upgrades_tenant_id ON firmware_upgrades(tenant_id);

        CREATE TABLE IF NOT EXISTS firmware_versions (
            version TEXT PRIMARY KEY,
            size TEXT,
            bugs_json TEXT,
            news_json TEXT,
            first_sync TEXT,
            last_sync TEXT,
            sync_id TEXT,
            client_id TEXT
        );

        CREATE TABLE IF NOT EXISTS firewall_groups (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            name TEXT,
            parent_group_id TEXT,
            locked_by_managing_account INTEGER NOT NULL DEFAULT 0,
            firewalls_total INTEGER,
            firewalls_items_count INTEGER,
            firewalls_items_json TEXT,
            config_import_json TEXT,
            created_by_json TEXT,
            updated_by_json TEXT,
            created_at TEXT,
            updated_at TEXT,
            first_sync TEXT,
            last_sync TEXT,
            sync_id TEXT,
            client_id TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );
        CREATE INDEX IF NOT EXISTS ix_firewall_groups_tenant_id ON firewall_groups(tenant_id);

        CREATE TABLE IF NOT EXISTS firewall_group_sync_status (
            group_id TEXT NOT NULL,
            firewall_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            status TEXT,
            last_updated_at TEXT,
            first_sync TEXT,
            last_sync TEXT,
            sync_id TEXT,
            client_id TEXT,
            PRIMARY KEY (group_id, firewall_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );
        CREATE INDEX IF NOT EXISTS ix_fgss_tenant_id ON firewall_group_sync_status(tenant_id);

        CREATE TABLE IF NOT EXISTS mdr_threat_feed_sync (
            firewall_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            transaction_id TEXT,
            poll_status TEXT,
            transaction_status TEXT,
            transaction_result TEXT,
            response_json TEXT,
            detail_message TEXT,
            first_sync TEXT,
            last_sync TEXT,
            sync_id TEXT,
            client_id TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );
        CREATE INDEX IF NOT EXISTS ix_mdr_threat_feed_tenant_id ON mdr_threat_feed_sync(tenant_id);

        CREATE TABLE IF NOT EXISTS tenant_roles (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            name TEXT,
            description TEXT,
            role_type TEXT,
            principal_type TEXT,
            permission_sets_json TEXT,
            created_at TEXT,
            updated_at TEXT,
            first_sync TEXT,
            last_sync TEXT,
            sync_id TEXT,
            client_id TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );
        CREATE INDEX IF NOT EXISTS ix_tenant_roles_tenant_id ON tenant_roles(tenant_id);

        CREATE TABLE IF NOT EXISTS tenant_admins (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            tenant_ref_json TEXT,
            profile_name TEXT,
            profile_first_name TEXT,
            profile_last_name TEXT,
            profile_email TEXT,
            users_json TEXT,
            role_assignments_json TEXT,
            created_at TEXT,
            updated_at TEXT,
            first_sync TEXT,
            last_sync TEXT,
            sync_id TEXT,
            client_id TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );
        CREATE INDEX IF NOT EXISTS ix_tenant_admins_tenant_id ON tenant_admins(tenant_id);

        CREATE TABLE IF NOT EXISTS sync_change_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sync_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            table_name TEXT NOT NULL,
            row_key_json TEXT NOT NULL,
            operation TEXT NOT NULL,
            column_name TEXT,
            old_value TEXT,
            new_value TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_sync_change_events_sync_id ON sync_change_events(sync_id);
        CREATE INDEX IF NOT EXISTS ix_sync_change_events_client_id ON sync_change_events(client_id);
    """)
    _migrate_sync_columns(conn)
    _ensure_sync_columns(conn)
    _ensure_client_id_column(conn)
    _drop_synced_at_column(conn)
    conn.commit()
    logger.debug("Schema initialized")


def _migrate_sync_columns(conn: sqlite3.Connection) -> None:
    """Rename old sync column names to first_sync, last_sync, sync_id if present."""
    renames = (
        ("added_timestamp", "first_sync"),
        ("updated_timestamp", "last_sync"),
        ("update_id", "sync_id"),
    )
    for table in (
        "tenants",
        "firewalls",
        "licenses",
        "license_subscriptions",
        "alerts",
        "alert_details",
        "firmware_upgrades",
        "firmware_versions",
        "firewall_groups",
        "firewall_group_sync_status",
        "mdr_threat_feed_sync",
        "tenant_roles",
        "tenant_admins",
    ):
        cur = conn.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in cur.fetchall()}
        for old_name, new_name in renames:
            if old_name in existing and new_name not in existing:
                conn.execute(f"ALTER TABLE {table} RENAME COLUMN {old_name} TO {new_name}")
                logger.debug("Renamed %s.%s to %s", table, old_name, new_name)


def _drop_synced_at_column(conn: sqlite3.Connection) -> None:
    """Drop synced_at column from tables that have it (SQLite 3.35+)."""
    for table in (
        "firewalls",
        "licenses",
        "license_subscriptions",
        "alerts",
        "alert_details",
        "firmware_upgrades",
        "firmware_versions",
        "firewall_groups",
        "firewall_group_sync_status",
        "mdr_threat_feed_sync",
        "tenant_roles",
        "tenant_admins",
    ):
        cur = conn.execute(f"PRAGMA table_info({table})")
        if any(row[1] == "synced_at" for row in cur.fetchall()):
            conn.execute(f"ALTER TABLE {table} DROP COLUMN synced_at")
            logger.debug("Dropped column synced_at from %s", table)


def _ensure_sync_columns(conn: sqlite3.Connection) -> None:
    """Add first_sync, last_sync, sync_id to existing tables if missing."""
    columns = ("first_sync TEXT", "last_sync TEXT", "sync_id TEXT")
    for table in (
        "tenants",
        "firewalls",
        "licenses",
        "license_subscriptions",
        "alerts",
        "alert_details",
        "firmware_upgrades",
        "firmware_versions",
        "firewall_groups",
        "firewall_group_sync_status",
        "mdr_threat_feed_sync",
        "tenant_roles",
        "tenant_admins",
    ):
        if not _table_exists(conn, table):
            continue
        cur = conn.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in cur.fetchall()}
        for col_spec in columns:
            name = col_spec.split()[0]
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_spec}")
                logger.debug("Added column %s to %s", name, table)


def _ensure_client_id_column(conn: sqlite3.Connection) -> None:
    """Add client_id (OAuth app used for sync) if missing."""
    for table in (
        "tenants",
        "firewalls",
        "licenses",
        "license_subscriptions",
        "alerts",
        "alert_details",
        "firmware_upgrades",
        "firmware_versions",
        "firewall_groups",
        "firewall_group_sync_status",
        "mdr_threat_feed_sync",
        "tenant_roles",
        "tenant_admins",
    ):
        if not _table_exists(conn, table):
            continue
        cur = conn.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in cur.fetchall()}
        if "client_id" not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN client_id TEXT")
            logger.debug("Added column client_id to %s", table)


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (name,),
    ).fetchone()
    return row is not None


def _insert_sync_change_event(
    conn: sqlite3.Connection,
    *,
    sync_id: str,
    client_id: str,
    occurred_at: str,
    table_name: str,
    row_key_json: str,
    operation: str,
    column_name: Optional[str],
    old_value: Optional[str],
    new_value: Optional[str],
) -> None:
    conn.execute(
        """
        INSERT INTO sync_change_events (
            sync_id, client_id, occurred_at, table_name, row_key_json,
            operation, column_name, old_value, new_value
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sync_id,
            client_id,
            occurred_at,
            table_name,
            row_key_json,
            operation,
            column_name,
            old_value,
            new_value,
        ),
    )


def _serialize_cell(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, (bytes, memoryview)):
        return bytes(val).decode("utf-8", errors="replace")
    return str(val)


def _cells_differ(a: Any, b: Any) -> bool:
    return _serialize_cell(a) != _serialize_cell(b)


def log_data_row_changes(
    conn: sqlite3.Connection,
    table: str,
    row_key: dict[str, Any],
    old: Optional[sqlite3.Row],
    new: Optional[sqlite3.Row],
) -> None:
    """Log insert (old is None), delete (new is None), or column updates between two rows."""
    ctx = _sync_change_ctx.get()
    if not ctx:
        return
    sync_id, client_id, ts = ctx
    rk = json.dumps(row_key, sort_keys=True, default=str)
    old_d = dict(old) if old else {}
    new_d = dict(new) if new else {}
    cols = sorted((set(old_d) | set(new_d)) - SYNC_META_COLUMNS)
    if old is None and new is None:
        return
    if old is None:
        payload = {c: new_d.get(c) for c in cols}
        _insert_sync_change_event(
            conn,
            sync_id=sync_id,
            client_id=client_id,
            occurred_at=ts,
            table_name=table,
            row_key_json=rk,
            operation="insert",
            column_name=None,
            old_value=None,
            new_value=json.dumps(payload, default=str),
        )
        return
    if new is None:
        payload = {c: old_d.get(c) for c in cols}
        _insert_sync_change_event(
            conn,
            sync_id=sync_id,
            client_id=client_id,
            occurred_at=ts,
            table_name=table,
            row_key_json=rk,
            operation="delete",
            column_name=None,
            old_value=json.dumps(payload, default=str),
            new_value=None,
        )
        return
    for c in cols:
        if _cells_differ(old_d.get(c), new_d.get(c)):
            _insert_sync_change_event(
                conn,
                sync_id=sync_id,
                client_id=client_id,
                occurred_at=ts,
                table_name=table,
                row_key_json=rk,
                operation="update",
                column_name=c,
                old_value=_serialize_cell(old_d.get(c)),
                new_value=_serialize_cell(new_d.get(c)),
            )


def _delete_rows_with_change_log(
    conn: sqlite3.Connection,
    table: str,
    sql_select: str,
    sql_delete: str,
    params: tuple[Any, ...],
    row_key_fn: Any,
) -> int:
    """Select rows matching sql_select, log delete for each, then run sql_delete with same params."""
    rows = list(conn.execute(sql_select, params))
    if not rows:
        return 0
    ctx = _sync_change_ctx.get()
    for r in rows:
        if ctx:
            log_data_row_changes(conn, table, row_key_fn(r), r, None)
    conn.execute(sql_delete, params)
    return len(rows)


def delete_stale_firewalls_for_tenant(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    tenant_id: str,
    keep_ids: set[str],
    api_ok: bool,
) -> None:
    if not api_ok:
        return
    if not keep_ids:
        _delete_rows_with_change_log(
            conn,
            "firewalls",
            "SELECT * FROM firewalls WHERE client_id = ? AND tenant_id = ?",
            "DELETE FROM firewalls WHERE client_id = ? AND tenant_id = ?",
            (client_id, tenant_id),
            lambda r: {"id": r["id"]},
        )
        return
    placeholders = ",".join("?" * len(keep_ids))
    params = (client_id, tenant_id, *tuple(keep_ids))
    _delete_rows_with_change_log(
        conn,
        "firewalls",
        f"SELECT * FROM firewalls WHERE client_id = ? AND tenant_id = ? AND id NOT IN ({placeholders})",
        f"DELETE FROM firewalls WHERE client_id = ? AND tenant_id = ? AND id NOT IN ({placeholders})",
        params,
        lambda r: {"id": r["id"]},
    )


def delete_stale_licenses_for_tenant(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    tenant_id: str,
    keep_serials: set[str],
    api_ok: bool,
) -> None:
    if not api_ok:
        return
    cur = conn.execute(
        "SELECT serial_number FROM licenses WHERE client_id = ? AND tenant_id = ?",
        (client_id, tenant_id),
    )
    stale = [r[0] for r in cur.fetchall() if r[0] not in keep_serials]
    for serial in stale:
        _delete_rows_with_change_log(
            conn,
            "license_subscriptions",
            "SELECT * FROM license_subscriptions WHERE client_id = ? AND serial_number = ?",
            "DELETE FROM license_subscriptions WHERE client_id = ? AND serial_number = ?",
            (client_id, serial),
            lambda r: {"id": r["id"]},
        )
        _delete_rows_with_change_log(
            conn,
            "licenses",
            "SELECT * FROM licenses WHERE client_id = ? AND serial_number = ?",
            "DELETE FROM licenses WHERE client_id = ? AND serial_number = ?",
            (client_id, serial),
            lambda r: {"serial_number": r["serial_number"]},
        )


def delete_stale_partner_licenses(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    partner_id: str,
    keep_serials: set[str],
    api_ok: bool,
) -> None:
    """Remove partner-scoped license rows (``tenant_id`` IS NULL) not returned by partner API."""
    if not api_ok:
        return
    cur = conn.execute(
        """
        SELECT serial_number FROM licenses
        WHERE client_id = ? AND partner_id = ? AND tenant_id IS NULL
        """,
        (client_id, partner_id),
    )
    stale = [r[0] for r in cur.fetchall() if r[0] not in keep_serials]
    for serial in stale:
        _delete_rows_with_change_log(
            conn,
            "license_subscriptions",
            "SELECT * FROM license_subscriptions WHERE client_id = ? AND serial_number = ?",
            "DELETE FROM license_subscriptions WHERE client_id = ? AND serial_number = ?",
            (client_id, serial),
            lambda r: {"id": r["id"]},
        )
        _delete_rows_with_change_log(
            conn,
            "licenses",
            "SELECT * FROM licenses WHERE client_id = ? AND serial_number = ?",
            "DELETE FROM licenses WHERE client_id = ? AND serial_number = ?",
            (client_id, serial),
            lambda r: {"serial_number": r["serial_number"]},
        )


def delete_stale_firmware_upgrades_for_tenant(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    tenant_id: str,
    keep_firewall_ids: set[str],
    api_ok: bool,
) -> None:
    if not api_ok:
        return
    if not keep_firewall_ids:
        _delete_rows_with_change_log(
            conn,
            "firmware_upgrades",
            "SELECT * FROM firmware_upgrades WHERE client_id = ? AND tenant_id = ?",
            "DELETE FROM firmware_upgrades WHERE client_id = ? AND tenant_id = ?",
            (client_id, tenant_id),
            lambda r: {"firewall_id": r["firewall_id"]},
        )
        return
    ph = ",".join("?" * len(keep_firewall_ids))
    params = (client_id, tenant_id, *tuple(keep_firewall_ids))
    _delete_rows_with_change_log(
        conn,
        "firmware_upgrades",
        f"SELECT * FROM firmware_upgrades WHERE client_id = ? AND tenant_id = ? AND firewall_id NOT IN ({ph})",
        f"DELETE FROM firmware_upgrades WHERE client_id = ? AND tenant_id = ? AND firewall_id NOT IN ({ph})",
        params,
        lambda r: {"firewall_id": r["firewall_id"]},
    )


def delete_stale_firmware_versions_for_client(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    keep_versions: set[str],
    prune: bool,
) -> None:
    """Drop firmware version rows for this client when a successful firmware check ran this sync."""
    if not prune:
        return
    if not keep_versions:
        _delete_rows_with_change_log(
            conn,
            "firmware_versions",
            "SELECT * FROM firmware_versions WHERE client_id = ?",
            "DELETE FROM firmware_versions WHERE client_id = ?",
            (client_id,),
            lambda r: {"version": r["version"]},
        )
        return
    ph = ",".join("?" * len(keep_versions))
    params = (client_id, *tuple(keep_versions))
    _delete_rows_with_change_log(
        conn,
        "firmware_versions",
        f"SELECT * FROM firmware_versions WHERE client_id = ? AND version NOT IN ({ph})",
        f"DELETE FROM firmware_versions WHERE client_id = ? AND version NOT IN ({ph})",
        params,
        lambda r: {"version": r["version"]},
    )


def delete_stale_firewall_groups_for_tenant(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    tenant_id: str,
    keep_ids: set[str],
    api_ok: bool,
) -> None:
    if not api_ok:
        return
    if not keep_ids:
        _delete_rows_with_change_log(
            conn,
            "firewall_groups",
            "SELECT * FROM firewall_groups WHERE client_id = ? AND tenant_id = ?",
            "DELETE FROM firewall_groups WHERE client_id = ? AND tenant_id = ?",
            (client_id, tenant_id),
            lambda r: {"id": r["id"]},
        )
        return
    ph = ",".join("?" * len(keep_ids))
    params = (client_id, tenant_id, *tuple(keep_ids))
    _delete_rows_with_change_log(
        conn,
        "firewall_groups",
        f"SELECT * FROM firewall_groups WHERE client_id = ? AND tenant_id = ? AND id NOT IN ({ph})",
        f"DELETE FROM firewall_groups WHERE client_id = ? AND tenant_id = ? AND id NOT IN ({ph})",
        params,
        lambda r: {"id": r["id"]},
    )


def delete_stale_tenant_roles_for_tenant(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    tenant_id: str,
    keep_ids: set[str],
    api_ok: bool,
) -> None:
    if not api_ok:
        return
    if not keep_ids:
        _delete_rows_with_change_log(
            conn,
            "tenant_roles",
            "SELECT * FROM tenant_roles WHERE client_id = ? AND tenant_id = ?",
            "DELETE FROM tenant_roles WHERE client_id = ? AND tenant_id = ?",
            (client_id, tenant_id),
            lambda r: {"id": r["id"]},
        )
        return
    ph = ",".join("?" * len(keep_ids))
    params = (client_id, tenant_id, *tuple(keep_ids))
    _delete_rows_with_change_log(
        conn,
        "tenant_roles",
        f"SELECT * FROM tenant_roles WHERE client_id = ? AND tenant_id = ? AND id NOT IN ({ph})",
        f"DELETE FROM tenant_roles WHERE client_id = ? AND tenant_id = ? AND id NOT IN ({ph})",
        params,
        lambda r: {"id": r["id"]},
    )


def delete_stale_tenant_admins_for_tenant(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    tenant_id: str,
    keep_ids: set[str],
    api_ok: bool,
) -> None:
    if not api_ok:
        return
    if not keep_ids:
        _delete_rows_with_change_log(
            conn,
            "tenant_admins",
            "SELECT * FROM tenant_admins WHERE client_id = ? AND tenant_id = ?",
            "DELETE FROM tenant_admins WHERE client_id = ? AND tenant_id = ?",
            (client_id, tenant_id),
            lambda r: {"id": r["id"]},
        )
        return
    ph = ",".join("?" * len(keep_ids))
    params = (client_id, tenant_id, *tuple(keep_ids))
    _delete_rows_with_change_log(
        conn,
        "tenant_admins",
        f"SELECT * FROM tenant_admins WHERE client_id = ? AND tenant_id = ? AND id NOT IN ({ph})",
        f"DELETE FROM tenant_admins WHERE client_id = ? AND tenant_id = ? AND id NOT IN ({ph})",
        params,
        lambda r: {"id": r["id"]},
    )


def delete_stale_firewall_group_sync_status_for_tenant(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    tenant_id: str,
    keep_pairs: set[tuple[str, str]],
    api_ok: bool,
) -> None:
    if not api_ok:
        return
    cur = conn.execute(
        "SELECT group_id, firewall_id FROM firewall_group_sync_status WHERE client_id = ? AND tenant_id = ?",
        (client_id, tenant_id),
    )
    for gid, fid in cur.fetchall():
        if (gid, fid) not in keep_pairs:
            _delete_rows_with_change_log(
                conn,
                "firewall_group_sync_status",
                "SELECT * FROM firewall_group_sync_status WHERE client_id = ? AND group_id = ? AND firewall_id = ?",
                "DELETE FROM firewall_group_sync_status WHERE client_id = ? AND group_id = ? AND firewall_id = ?",
                (client_id, gid, fid),
                lambda r: {"group_id": r["group_id"], "firewall_id": r["firewall_id"]},
            )


def delete_stale_mdr_for_tenant(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    tenant_id: str,
    keep_firewall_ids: set[str],
    sync_mdr: bool,
    api_ok: bool,
) -> None:
    if not sync_mdr or not api_ok:
        return
    if not keep_firewall_ids:
        _delete_rows_with_change_log(
            conn,
            "mdr_threat_feed_sync",
            "SELECT * FROM mdr_threat_feed_sync WHERE client_id = ? AND tenant_id = ?",
            "DELETE FROM mdr_threat_feed_sync WHERE client_id = ? AND tenant_id = ?",
            (client_id, tenant_id),
            lambda r: {"firewall_id": r["firewall_id"]},
        )
        return
    ph = ",".join("?" * len(keep_firewall_ids))
    params = (client_id, tenant_id, *tuple(keep_firewall_ids))
    _delete_rows_with_change_log(
        conn,
        "mdr_threat_feed_sync",
        f"SELECT * FROM mdr_threat_feed_sync WHERE client_id = ? AND tenant_id = ? AND firewall_id NOT IN ({ph})",
        f"DELETE FROM mdr_threat_feed_sync WHERE client_id = ? AND tenant_id = ? AND firewall_id NOT IN ({ph})",
        params,
        lambda r: {"firewall_id": r["firewall_id"]},
    )


def cascade_delete_tenant_for_client(
    conn: sqlite3.Connection, tenant_id: str, client_id: str
) -> None:
    """Remove all synced data for a tenant row and the tenant itself (orphan from tenant list)."""
    _delete_rows_with_change_log(
        conn,
        "firewall_group_sync_status",
        "SELECT * FROM firewall_group_sync_status WHERE client_id = ? AND tenant_id = ?",
        "DELETE FROM firewall_group_sync_status WHERE client_id = ? AND tenant_id = ?",
        (client_id, tenant_id),
        lambda r: {"group_id": r["group_id"], "firewall_id": r["firewall_id"]},
    )
    _delete_rows_with_change_log(
        conn,
        "firmware_upgrades",
        "SELECT * FROM firmware_upgrades WHERE client_id = ? AND tenant_id = ?",
        "DELETE FROM firmware_upgrades WHERE client_id = ? AND tenant_id = ?",
        (client_id, tenant_id),
        lambda r: {"firewall_id": r["firewall_id"]},
    )
    _delete_rows_with_change_log(
        conn,
        "mdr_threat_feed_sync",
        "SELECT * FROM mdr_threat_feed_sync WHERE client_id = ? AND tenant_id = ?",
        "DELETE FROM mdr_threat_feed_sync WHERE client_id = ? AND tenant_id = ?",
        (client_id, tenant_id),
        lambda r: {"firewall_id": r["firewall_id"]},
    )
    _delete_rows_with_change_log(
        conn,
        "firewalls",
        "SELECT * FROM firewalls WHERE client_id = ? AND tenant_id = ?",
        "DELETE FROM firewalls WHERE client_id = ? AND tenant_id = ?",
        (client_id, tenant_id),
        lambda r: {"id": r["id"]},
    )
    _delete_rows_with_change_log(
        conn,
        "firewall_groups",
        "SELECT * FROM firewall_groups WHERE client_id = ? AND tenant_id = ?",
        "DELETE FROM firewall_groups WHERE client_id = ? AND tenant_id = ?",
        (client_id, tenant_id),
        lambda r: {"id": r["id"]},
    )
    _delete_rows_with_change_log(
        conn,
        "alert_details",
        "SELECT * FROM alert_details WHERE client_id = ? AND tenant_id = ?",
        "DELETE FROM alert_details WHERE client_id = ? AND tenant_id = ?",
        (client_id, tenant_id),
        lambda r: {"id": r["id"]},
    )
    _delete_rows_with_change_log(
        conn,
        "alerts",
        "SELECT * FROM alerts WHERE client_id = ? AND tenant_id = ?",
        "DELETE FROM alerts WHERE client_id = ? AND tenant_id = ?",
        (client_id, tenant_id),
        lambda r: {"id": r["id"]},
    )
    cur = conn.execute(
        "SELECT serial_number FROM licenses WHERE client_id = ? AND tenant_id = ?",
        (client_id, tenant_id),
    )
    for (serial,) in cur.fetchall():
        _delete_rows_with_change_log(
            conn,
            "license_subscriptions",
            "SELECT * FROM license_subscriptions WHERE client_id = ? AND serial_number = ?",
            "DELETE FROM license_subscriptions WHERE client_id = ? AND serial_number = ?",
            (client_id, serial),
            lambda r: {"id": r["id"]},
        )
        _delete_rows_with_change_log(
            conn,
            "licenses",
            "SELECT * FROM licenses WHERE client_id = ? AND serial_number = ?",
            "DELETE FROM licenses WHERE client_id = ? AND serial_number = ?",
            (client_id, serial),
            lambda r: {"serial_number": r["serial_number"]},
        )
    _delete_rows_with_change_log(
        conn,
        "tenants",
        "SELECT * FROM tenants WHERE client_id = ? AND id = ?",
        "DELETE FROM tenants WHERE client_id = ? AND id = ?",
        (client_id, tenant_id),
        lambda r: {"id": r["id"]},
    )


def delete_stale_tenants_for_partner(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    keep_tenant_ids: set[str],
    api_ok: bool,
) -> None:
    if not api_ok:
        return
    cur = conn.execute(
        "SELECT id FROM tenants WHERE client_id = ?",
        (client_id,),
    )
    stale = [r[0] for r in cur.fetchall() if r[0] not in keep_tenant_ids]
    for tid in stale:
        cascade_delete_tenant_for_client(conn, tid, client_id)


def delete_stale_license_subscriptions_for_serial(
    conn: sqlite3.Connection,
    *,
    serial_number: str,
    client_id: str,
    keep_sub_ids: set[str],
) -> None:
    """After upserting a license, remove subscription rows not present in the API payload."""
    cur = conn.execute(
        "SELECT * FROM license_subscriptions WHERE serial_number = ? AND client_id = ?",
        (serial_number, client_id),
    )
    for r in cur.fetchall():
        if r["id"] not in keep_sub_ids:
            if _sync_change_ctx.get():
                log_data_row_changes(
                    conn,
                    "license_subscriptions",
                    {"id": r["id"]},
                    r,
                    None,
                )
            conn.execute(
                "DELETE FROM license_subscriptions WHERE id = ?",
                (r["id"],),
            )


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def upsert_tenant(
    conn: sqlite3.Connection,
    tenant: Any,
    *,
    client_id: str,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Insert or replace a tenant. Accepts central.classes.Tenant or dict-like."""
    tid = _get(tenant, "id") or "unknown"
    old = (
        conn.execute("SELECT * FROM tenants WHERE id = ?", (tid,)).fetchone()
        if _sync_change_ctx.get()
        else None
    )
    contact = _get(tenant, "contact")
    if contact is not None and not isinstance(contact, (str, type(None))):
        try:
            contact = getattr(contact, "__dict__", contact)
            if not hasattr(contact, "get"):
                contact = dict(contact) if contact else None
        except Exception:
            contact = str(contact)
    contact_json = _to_json(contact)

    external_ids = _get(tenant, "externalIds")
    products = _get(tenant, "products")
    if products is not None:
        products = [_get(p, "code") or p for p in products] if products else None

    row = (
        tid,
        _get(tenant, "showAs"),
        _get(tenant, "name") or "Unknown",
        _get(tenant, "dataGeography"),
        _get(tenant, "dataRegion"),
        _get(tenant, "billingType"),
        _get_nested(tenant, "partner", "id"),
        _get_nested(tenant, "organization", "id"),
        _get(tenant, "apiHost"),
        _get(tenant, "status"),
        contact_json,
        _to_json(external_ids),
        _to_json(products),
        _now_utc(),
        run_timestamp,
        run_timestamp,
        update_id,
        client_id,
    )
    conn.execute(
        """
        INSERT INTO tenants (
            id, show_as, name, data_geography, data_region, billing_type,
            partner_id, organization_id, api_host, status, contact_json,
            external_ids_json, products_json, updated_at,
            first_sync, last_sync, sync_id, client_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            show_as = excluded.show_as,
            name = excluded.name,
            data_geography = excluded.data_geography,
            data_region = excluded.data_region,
            billing_type = excluded.billing_type,
            partner_id = excluded.partner_id,
            organization_id = excluded.organization_id,
            api_host = excluded.api_host,
            status = excluded.status,
            contact_json = excluded.contact_json,
            external_ids_json = excluded.external_ids_json,
            products_json = excluded.products_json,
            updated_at = excluded.updated_at,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id,
            client_id = excluded.client_id
        """,
        row,
    )
    if _sync_change_ctx.get():
        new = conn.execute("SELECT * FROM tenants WHERE id = ?", (tid,)).fetchone()
        log_data_row_changes(conn, "tenants", {"id": tid}, old, new)


def upsert_firewall(
    conn: sqlite3.Connection,
    firewall: Any,
    *,
    client_id: str,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Insert or replace a firewall. Accepts central.firewalls.classes.Firewall."""
    old = (
        conn.execute(
            "SELECT * FROM firewalls WHERE id = ?", (firewall.id,)
        ).fetchone()
        if _sync_change_ctx.get()
        else None
    )
    tenant_id = getattr(getattr(firewall, "tenant", None), "id", None) or (getattr(firewall, "tenant") or {}).get("id")
    group = getattr(firewall, "group", None)
    group_id = getattr(group, "id", None) if group else None
    group_name = getattr(group, "name", None) if group else None
    status = getattr(firewall, "status", None)
    geo = getattr(firewall, "geoLocation", None)

    row = (
        firewall.id,
        tenant_id,
        firewall.serialNumber,
        group_id,
        group_name,
        getattr(firewall, "hostname", None),
        getattr(firewall, "name", None),
        _to_json(getattr(firewall, "externalIpv4Addresses", None)),
        getattr(firewall, "firmwareVersion", None),
        getattr(firewall, "model", None),
        getattr(status, "managingStatus", None) if status else None,
        getattr(status, "reportingStatus", None) if status else None,
        1 if (status and getattr(status, "connected", False)) else 0,
        1 if (status and getattr(status, "suspended", False)) else 0,
        getattr(firewall, "stateChangedAt", None),
        _to_json(getattr(firewall, "capabilities", None)),
        getattr(geo, "latitude", None) if geo else None,
        getattr(geo, "longitude", None) if geo else None,
        getattr(firewall, "createdAt", None),
        getattr(firewall, "updatedAt", None),
        run_timestamp,
        run_timestamp,
        update_id,
        client_id,
    )
    conn.execute(
        """
        INSERT INTO firewalls (
            id, tenant_id, serial_number, group_id, group_name, hostname, name,
            external_ipv4_addresses_json, firmware_version, model,
            managing_status, reporting_status, connected, suspended,
            state_changed_at, capabilities_json, geo_latitude, geo_longitude,
            created_at, updated_at,
            first_sync, last_sync, sync_id, client_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            tenant_id = excluded.tenant_id,
            serial_number = excluded.serial_number,
            group_id = excluded.group_id,
            group_name = excluded.group_name,
            hostname = excluded.hostname,
            name = excluded.name,
            external_ipv4_addresses_json = excluded.external_ipv4_addresses_json,
            firmware_version = excluded.firmware_version,
            model = excluded.model,
            managing_status = excluded.managing_status,
            reporting_status = excluded.reporting_status,
            connected = excluded.connected,
            suspended = excluded.suspended,
            state_changed_at = excluded.state_changed_at,
            capabilities_json = excluded.capabilities_json,
            geo_latitude = excluded.geo_latitude,
            geo_longitude = excluded.geo_longitude,
            created_at = excluded.created_at,
            updated_at = excluded.updated_at,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id,
            client_id = excluded.client_id
        """,
        row,
    )
    if _sync_change_ctx.get():
        new = conn.execute(
            "SELECT * FROM firewalls WHERE id = ?", (firewall.id,)
        ).fetchone()
        log_data_row_changes(conn, "firewalls", {"id": firewall.id}, old, new)


def upsert_license(
    conn: sqlite3.Connection,
    license_obj: Any,
    *,
    client_id: str,
    update_id: str,
    run_timestamp: str,
    tenant_id: Optional[str] = None,
    partner_id: Optional[str] = None,
) -> None:
    """Insert or replace a license header and all its subscriptions."""
    serial = license_obj.serialNumber
    tenant_id = tenant_id or (getattr(license_obj.tenant, "id", None) if getattr(license_obj, "tenant", None) else None)
    partner_id = partner_id or (getattr(license_obj.partner, "id", None) if getattr(license_obj, "partner", None) else None)
    org_id = getattr(license_obj.organization, "id", None) if getattr(license_obj, "organization", None) else None

    old_lic = (
        conn.execute(
            "SELECT * FROM licenses WHERE serial_number = ?", (serial,)
        ).fetchone()
        if _sync_change_ctx.get()
        else None
    )
    conn.execute(
        """
        INSERT INTO licenses (
            serial_number, tenant_id, partner_id, organization_id,
            model, model_type, last_seen_at,
            first_sync, last_sync, sync_id, client_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(serial_number) DO UPDATE SET
            tenant_id = excluded.tenant_id,
            partner_id = excluded.partner_id,
            organization_id = excluded.organization_id,
            model = excluded.model,
            model_type = excluded.model_type,
            last_seen_at = excluded.last_seen_at,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id,
            client_id = excluded.client_id
        """,
        (
            serial,
            tenant_id,
            partner_id,
            org_id,
            license_obj.model,
            getattr(license_obj, "modelType", None),
            getattr(license_obj, "lastSeenAt", None),
            run_timestamp,
            run_timestamp,
            update_id,
            client_id,
        ),
    )
    if _sync_change_ctx.get():
        new_lic = conn.execute(
            "SELECT * FROM licenses WHERE serial_number = ?", (serial,)
        ).fetchone()
        log_data_row_changes(
            conn, "licenses", {"serial_number": serial}, old_lic, new_lic
        )

    subs = getattr(license_obj, "licenses", None) or []
    for sub in subs:
        old_sub = (
            conn.execute(
                "SELECT * FROM license_subscriptions WHERE id = ?", (sub.id,)
            ).fetchone()
            if _sync_change_ctx.get()
            else None
        )
        product = getattr(sub, "product", None)
        product_code = getattr(product, "code", None) if product else None
        product_name = getattr(product, "name", None) if product else None
        usage = getattr(sub, "usage", None)
        usage_current = getattr(usage, "current", None) if usage else None
        usage_count = getattr(usage_current, "count", None) if usage_current else None
        usage_date = getattr(usage_current, "date", None) if usage_current else None
        if usage_date is not None and hasattr(usage_date, "isoformat"):
            usage_date = usage_date.isoformat()

        conn.execute(
            """
            INSERT INTO license_subscriptions (
                id, serial_number, license_identifier, product_code, product_name,
                start_date, end_date, perpetual, type, quantity,
                usage_count, usage_date, unlimited,
                first_sync, last_sync, sync_id, client_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                serial_number = excluded.serial_number,
                license_identifier = excluded.license_identifier,
                product_code = excluded.product_code,
                product_name = excluded.product_name,
                start_date = excluded.start_date,
                end_date = excluded.end_date,
                perpetual = excluded.perpetual,
                type = excluded.type,
                quantity = excluded.quantity,
                usage_count = excluded.usage_count,
                usage_date = excluded.usage_date,
                unlimited = excluded.unlimited,
                last_sync = excluded.last_sync,
                sync_id = excluded.sync_id,
                client_id = excluded.client_id
            """,
            (
                sub.id,
                serial,
                getattr(sub, "licenseIdentifier", None),
                product_code,
                product_name,
                getattr(sub, "startDate", None),
                getattr(sub, "endDate", None),
                1 if getattr(sub, "perpetual", False) else 0,
                getattr(sub, "type", None),
                getattr(sub, "quantity", None),
                usage_count,
                usage_date,
                1 if getattr(sub, "unlimited", False) else 0,
                run_timestamp,
                run_timestamp,
                update_id,
                client_id,
            ),
        )
        if _sync_change_ctx.get():
            new_sub = conn.execute(
                "SELECT * FROM license_subscriptions WHERE id = ?", (sub.id,)
            ).fetchone()
            log_data_row_changes(
                conn,
                "license_subscriptions",
                {"id": sub.id},
                old_sub,
                new_sub,
            )

    delete_stale_license_subscriptions_for_serial(
        conn,
        serial_number=serial,
        client_id=client_id,
        keep_sub_ids={sub.id for sub in subs},
    )


def upsert_alert(
    conn: sqlite3.Connection,
    alert: Any,
    *,
    client_id: str,
    tenant_id: Optional[str] = None,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Insert or replace an alert. Accepts central.alerts.classes.Alert or dict-like."""
    aid = _get(alert, "id") or "unknown"
    old = (
        conn.execute("SELECT * FROM alerts WHERE id = ?", (aid,)).fetchone()
        if _sync_change_ctx.get()
        else None
    )
    tenant_ref = _get(alert, "tenant")
    tid = tenant_id or (_get_nested(tenant_ref, "id") if tenant_ref else None)
    managed_json = _to_json(_get(alert, "managedAgent"))
    person_json = _to_json(_get(alert, "person"))
    tenant_ref_json = _to_json(tenant_ref)

    row = (
        aid,
        tid,
        _get(alert, "category"),
        _get(alert, "description"),
        _get(alert, "groupKey"),
        _get(alert, "product"),
        _get(alert, "raisedAt"),
        _get(alert, "severity"),
        _get(alert, "type"),
        _to_json(_get(alert, "allowedActions")),
        managed_json,
        person_json,
        tenant_ref_json,
        run_timestamp,
        run_timestamp,
        update_id,
        client_id,
    )
    conn.execute(
        """
        INSERT INTO alerts (
            id, tenant_id, category, description, group_key, product,
            raised_at, severity, type, allowed_actions_json,
            managed_agent_json, person_json, tenant_ref_json,
            first_sync, last_sync, sync_id, client_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            tenant_id = excluded.tenant_id,
            category = excluded.category,
            description = excluded.description,
            group_key = excluded.group_key,
            product = excluded.product,
            raised_at = excluded.raised_at,
            severity = excluded.severity,
            type = excluded.type,
            allowed_actions_json = excluded.allowed_actions_json,
            managed_agent_json = excluded.managed_agent_json,
            person_json = excluded.person_json,
            tenant_ref_json = excluded.tenant_ref_json,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id,
            client_id = excluded.client_id
        """,
        row,
    )
    if _sync_change_ctx.get():
        new = conn.execute("SELECT * FROM alerts WHERE id = ?", (aid,)).fetchone()
        log_data_row_changes(conn, "alerts", {"id": aid}, old, new)


def upsert_alert_detail(
    conn: sqlite3.Connection,
    alert: Any,
    *,
    client_id: str,
    tenant_id: Optional[str] = None,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Insert or replace a row in alert_details (full alert from get_alert). Same shape as alerts."""
    aid = _get(alert, "id") or "unknown"
    old = (
        conn.execute("SELECT * FROM alert_details WHERE id = ?", (aid,)).fetchone()
        if _sync_change_ctx.get()
        else None
    )
    tenant_ref = _get(alert, "tenant")
    tid = tenant_id or (_get_nested(tenant_ref, "id") if tenant_ref else None)
    managed_json = _to_json(_get(alert, "managedAgent"))
    person_json = _to_json(_get(alert, "person"))
    tenant_ref_json = _to_json(tenant_ref)

    row = (
        aid,
        tid,
        _get(alert, "category"),
        _get(alert, "description"),
        _get(alert, "groupKey"),
        _get(alert, "product"),
        _get(alert, "raisedAt"),
        _get(alert, "severity"),
        _get(alert, "type"),
        _to_json(_get(alert, "allowedActions")),
        managed_json,
        person_json,
        tenant_ref_json,
        run_timestamp,
        run_timestamp,
        update_id,
        client_id,
    )
    conn.execute(
        """
        INSERT INTO alert_details (
            id, tenant_id, category, description, group_key, product,
            raised_at, severity, type, allowed_actions_json,
            managed_agent_json, person_json, tenant_ref_json,
            first_sync, last_sync, sync_id, client_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            tenant_id = excluded.tenant_id,
            category = excluded.category,
            description = excluded.description,
            group_key = excluded.group_key,
            product = excluded.product,
            raised_at = excluded.raised_at,
            severity = excluded.severity,
            type = excluded.type,
            allowed_actions_json = excluded.allowed_actions_json,
            managed_agent_json = excluded.managed_agent_json,
            person_json = excluded.person_json,
            tenant_ref_json = excluded.tenant_ref_json,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id,
            client_id = excluded.client_id
        """,
        row,
    )
    if _sync_change_ctx.get():
        new = conn.execute(
            "SELECT * FROM alert_details WHERE id = ?", (aid,)
        ).fetchone()
        log_data_row_changes(conn, "alert_details", {"id": aid}, old, new)


def upsert_firmware_upgrade(
    conn: sqlite3.Connection,
    upgrade: Any,
    *,
    client_id: str,
    tenant_id: str,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Insert or replace a firewall firmware upgrade row. Accepts FirewallUpgrade."""
    old = (
        conn.execute(
            "SELECT * FROM firmware_upgrades WHERE firewall_id = ?", (upgrade.id,)
        ).fetchone()
        if _sync_change_ctx.get()
        else None
    )
    upgrade_to = getattr(upgrade, "upgradeToVersion", None) or []
    row = (
        upgrade.id,
        tenant_id,
        upgrade.serialNumber,
        getattr(upgrade, "firmwareVersion", None),
        _to_json(upgrade_to),
        run_timestamp,
        run_timestamp,
        update_id,
        client_id,
    )
    conn.execute(
        """
        INSERT INTO firmware_upgrades (
            firewall_id, tenant_id, serial_number, current_version,
            upgrade_to_versions_json,
            first_sync, last_sync, sync_id, client_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(firewall_id) DO UPDATE SET
            tenant_id = excluded.tenant_id,
            serial_number = excluded.serial_number,
            current_version = excluded.current_version,
            upgrade_to_versions_json = excluded.upgrade_to_versions_json,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id,
            client_id = excluded.client_id
        """,
        row,
    )
    if _sync_change_ctx.get():
        new = conn.execute(
            "SELECT * FROM firmware_upgrades WHERE firewall_id = ?",
            (upgrade.id,),
        ).fetchone()
        log_data_row_changes(
            conn,
            "firmware_upgrades",
            {"firewall_id": upgrade.id},
            old,
            new,
        )


def upsert_firmware_version(
    conn: sqlite3.Connection,
    fw_version: Any,
    *,
    client_id: str,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Insert or replace a firmware version (release notes). Accepts FirmwareVersion."""
    ver = fw_version.version
    old = (
        conn.execute(
            "SELECT * FROM firmware_versions WHERE version = ?", (ver,)
        ).fetchone()
        if _sync_change_ctx.get()
        else None
    )
    row = (
        fw_version.version,
        getattr(fw_version, "size", None),
        _to_json(getattr(fw_version, "bugs", None)),
        _to_json(getattr(fw_version, "news", None)),
        run_timestamp,
        run_timestamp,
        update_id,
        client_id,
    )
    conn.execute(
        """
        INSERT INTO firmware_versions (
            version, size, bugs_json, news_json,
            first_sync, last_sync, sync_id, client_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(version) DO UPDATE SET
            size = excluded.size,
            bugs_json = excluded.bugs_json,
            news_json = excluded.news_json,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id,
            client_id = excluded.client_id
        """,
        row,
    )
    if _sync_change_ctx.get():
        new = conn.execute(
            "SELECT * FROM firmware_versions WHERE version = ?", (ver,)
        ).fetchone()
        log_data_row_changes(
            conn, "firmware_versions", {"version": ver}, old, new
        )


def _scalar_text(val: Any) -> Optional[str]:
    if val is None:
        return None
    if hasattr(val, "isoformat"):
        try:
            return val.isoformat()
        except Exception:
            return str(val)
    return str(val)


def upsert_firewall_group(
    conn: sqlite3.Connection,
    group: Any,
    *,
    tenant_id: str,
    client_id: str,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Persist a firewall group from ``get_firewall_groups`` (object or dict-like)."""
    gid = _get(group, "id") or "unknown"
    old = (
        conn.execute(
            "SELECT * FROM firewall_groups WHERE id = ?", (gid,)
        ).fetchone()
        if _sync_change_ctx.get()
        else None
    )
    parent = _get(group, "parentGroup")
    parent_id = _get(parent, "id") if parent else None
    fws = _get(group, "firewalls")
    total = _get(fws, "total") if fws is not None else None
    items_count = _get(fws, "itemsCount") if fws is not None else None
    items = _get(fws, "items") if fws is not None else None

    row = (
        gid,
        tenant_id,
        _get(group, "name"),
        parent_id,
        1 if _get(group, "lockedByManagingAccount") else 0,
        total,
        items_count,
        _to_json(items),
        _to_json(_get(group, "configImport")),
        _to_json(_get(group, "createdBy")),
        _to_json(_get(group, "updatedBy")),
        _scalar_text(_get(group, "createdAt")),
        _scalar_text(_get(group, "updatedAt")),
        run_timestamp,
        run_timestamp,
        update_id,
        client_id,
    )
    conn.execute(
        """
        INSERT INTO firewall_groups (
            id, tenant_id, name, parent_group_id, locked_by_managing_account,
            firewalls_total, firewalls_items_count, firewalls_items_json,
            config_import_json, created_by_json, updated_by_json,
            created_at, updated_at,
            first_sync, last_sync, sync_id, client_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            tenant_id = excluded.tenant_id,
            name = excluded.name,
            parent_group_id = excluded.parent_group_id,
            locked_by_managing_account = excluded.locked_by_managing_account,
            firewalls_total = excluded.firewalls_total,
            firewalls_items_count = excluded.firewalls_items_count,
            firewalls_items_json = excluded.firewalls_items_json,
            config_import_json = excluded.config_import_json,
            created_by_json = excluded.created_by_json,
            updated_by_json = excluded.updated_by_json,
            created_at = excluded.created_at,
            updated_at = excluded.updated_at,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id,
            client_id = excluded.client_id
        """,
        row,
    )
    if _sync_change_ctx.get():
        new = conn.execute(
            "SELECT * FROM firewall_groups WHERE id = ?", (gid,)
        ).fetchone()
        log_data_row_changes(conn, "firewall_groups", {"id": gid}, old, new)


def update_firewall_group_items_json_from_sync(
    conn: sqlite3.Connection,
    group_id: str,
    items: list[Any],
) -> None:
    """Set ``firewalls_items_json`` and counts from sync-status membership (API list may omit ``firewalls.items``)."""
    n = len(items)
    payload = json.dumps(items)
    old = (
        conn.execute(
            "SELECT * FROM firewall_groups WHERE id = ?", (group_id,)
        ).fetchone()
        if _sync_change_ctx.get()
        else None
    )
    conn.execute(
        """
        UPDATE firewall_groups SET
            firewalls_items_json = ?,
            firewalls_items_count = ?,
            firewalls_total = ?
        WHERE id = ?
        """,
        (payload, n, n, group_id),
    )
    if _sync_change_ctx.get() and old is not None:
        new = conn.execute(
            "SELECT * FROM firewall_groups WHERE id = ?", (group_id,)
        ).fetchone()
        if new is not None:
            log_data_row_changes(
                conn,
                "firewall_groups",
                {"id": group_id},
                old,
                new,
            )


def upsert_firewall_group_sync_status(
    conn: sqlite3.Connection,
    *,
    group_id: str,
    firewall_id: str,
    tenant_id: str,
    status: Optional[str],
    last_updated_at: Optional[str],
    client_id: str,
    update_id: str,
    run_timestamp: str,
) -> None:
    """One row per (group, firewall) from ``get_firewall_group_sync_status``."""
    old = (
        conn.execute(
            """
            SELECT * FROM firewall_group_sync_status
            WHERE group_id = ? AND firewall_id = ?
            """,
            (group_id, firewall_id),
        ).fetchone()
        if _sync_change_ctx.get()
        else None
    )
    conn.execute(
        """
        INSERT INTO firewall_group_sync_status (
            group_id, firewall_id, tenant_id, status, last_updated_at,
            first_sync, last_sync, sync_id, client_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(group_id, firewall_id) DO UPDATE SET
            tenant_id = excluded.tenant_id,
            status = excluded.status,
            last_updated_at = excluded.last_updated_at,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id,
            client_id = excluded.client_id
        """,
        (
            group_id,
            firewall_id,
            tenant_id,
            status,
            last_updated_at,
            run_timestamp,
            run_timestamp,
            update_id,
            client_id,
        ),
    )
    if _sync_change_ctx.get():
        new = conn.execute(
            """
            SELECT * FROM firewall_group_sync_status
            WHERE group_id = ? AND firewall_id = ?
            """,
            (group_id, firewall_id),
        ).fetchone()
        log_data_row_changes(
            conn,
            "firewall_group_sync_status",
            {"group_id": group_id, "firewall_id": firewall_id},
            old,
            new,
        )


def upsert_tenant_role(
    conn: sqlite3.Connection,
    role: Any,
    *,
    tenant_id: str,
    client_id: str,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Persist a role from ``get_roles`` (object with API-shaped attributes or dict)."""
    rid = _get(role, "id") or "unknown"
    old = (
        conn.execute("SELECT * FROM tenant_roles WHERE id = ?", (rid,)).fetchone()
        if _sync_change_ctx.get()
        else None
    )
    perm = _get(role, "permissionSets")
    row = (
        rid,
        tenant_id,
        _get(role, "name"),
        _get(role, "description"),
        _get(role, "type"),
        _get(role, "principalType"),
        _to_json(perm if perm is not None else []),
        _scalar_text(_get(role, "createdAt")),
        _scalar_text(_get(role, "updatedAt")),
        run_timestamp,
        run_timestamp,
        update_id,
        client_id,
    )
    conn.execute(
        """
        INSERT INTO tenant_roles (
            id, tenant_id, name, description, role_type, principal_type,
            permission_sets_json, created_at, updated_at,
            first_sync, last_sync, sync_id, client_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            tenant_id = excluded.tenant_id,
            name = excluded.name,
            description = excluded.description,
            role_type = excluded.role_type,
            principal_type = excluded.principal_type,
            permission_sets_json = excluded.permission_sets_json,
            created_at = excluded.created_at,
            updated_at = excluded.updated_at,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id,
            client_id = excluded.client_id
        """,
        row,
    )
    if _sync_change_ctx.get():
        new = conn.execute(
            "SELECT * FROM tenant_roles WHERE id = ?", (rid,)
        ).fetchone()
        log_data_row_changes(conn, "tenant_roles", {"id": rid}, old, new)


def upsert_tenant_admin(
    conn: sqlite3.Connection,
    admin: Any,
    *,
    tenant_id: str,
    client_id: str,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Persist an admin from ``get_admins``."""
    aid = _get(admin, "id") or "unknown"
    old = (
        conn.execute("SELECT * FROM tenant_admins WHERE id = ?", (aid,)).fetchone()
        if _sync_change_ctx.get()
        else None
    )
    tenant_ref = _get(admin, "tenant")
    profile = _get(admin, "profile") or {}
    users = _get(admin, "users")
    ra = _get(admin, "roleAssignments")
    row = (
        aid,
        tenant_id,
        _to_json(tenant_ref),
        _get(profile, "name"),
        _get(profile, "firstName"),
        _get(profile, "lastName"),
        _get(profile, "email"),
        _to_json(users if users is not None else []),
        _to_json(ra if ra is not None else []),
        _scalar_text(_get(admin, "createdAt")),
        _scalar_text(_get(admin, "updatedAt")),
        run_timestamp,
        run_timestamp,
        update_id,
        client_id,
    )
    conn.execute(
        """
        INSERT INTO tenant_admins (
            id, tenant_id, tenant_ref_json, profile_name, profile_first_name,
            profile_last_name, profile_email, users_json, role_assignments_json,
            created_at, updated_at,
            first_sync, last_sync, sync_id, client_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            tenant_id = excluded.tenant_id,
            tenant_ref_json = excluded.tenant_ref_json,
            profile_name = excluded.profile_name,
            profile_first_name = excluded.profile_first_name,
            profile_last_name = excluded.profile_last_name,
            profile_email = excluded.profile_email,
            users_json = excluded.users_json,
            role_assignments_json = excluded.role_assignments_json,
            created_at = excluded.created_at,
            updated_at = excluded.updated_at,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id,
            client_id = excluded.client_id
        """,
        row,
    )
    if _sync_change_ctx.get():
        new = conn.execute(
            "SELECT * FROM tenant_admins WHERE id = ?", (aid,)
        ).fetchone()
        log_data_row_changes(conn, "tenant_admins", {"id": aid}, old, new)


def upsert_mdr_threat_feed_sync(
    conn: sqlite3.Connection,
    *,
    firewall_id: str,
    tenant_id: str,
    client_id: str,
    update_id: str,
    run_timestamp: str,
    transaction_id: Optional[str] = None,
    poll_status: Optional[str] = None,
    transaction_status: Optional[str] = None,
    transaction_result: Optional[str] = None,
    response_json: Optional[str] = None,
    detail_message: Optional[str] = None,
) -> None:
    """Latest MDR threat-feed fetch + transaction poll outcome per firewall."""
    old = (
        conn.execute(
            "SELECT * FROM mdr_threat_feed_sync WHERE firewall_id = ?",
            (firewall_id,),
        ).fetchone()
        if _sync_change_ctx.get()
        else None
    )
    conn.execute(
        """
        INSERT INTO mdr_threat_feed_sync (
            firewall_id, tenant_id, transaction_id, poll_status,
            transaction_status, transaction_result, response_json, detail_message,
            first_sync, last_sync, sync_id, client_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(firewall_id) DO UPDATE SET
            tenant_id = excluded.tenant_id,
            transaction_id = excluded.transaction_id,
            poll_status = excluded.poll_status,
            transaction_status = excluded.transaction_status,
            transaction_result = excluded.transaction_result,
            response_json = excluded.response_json,
            detail_message = excluded.detail_message,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id,
            client_id = excluded.client_id
        """,
        (
            firewall_id,
            tenant_id,
            transaction_id,
            poll_status,
            transaction_status,
            transaction_result,
            response_json,
            detail_message,
            run_timestamp,
            run_timestamp,
            update_id,
            client_id,
        ),
    )
    if _sync_change_ctx.get():
        new = conn.execute(
            "SELECT * FROM mdr_threat_feed_sync WHERE firewall_id = ?",
            (firewall_id,),
        ).fetchone()
        log_data_row_changes(
            conn,
            "mdr_threat_feed_sync",
            {"firewall_id": firewall_id},
            old,
            new,
        )
