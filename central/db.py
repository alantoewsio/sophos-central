"""SQLite persistence for tenants, firewalls, and licenses with upsert support."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

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
    if hasattr(obj, attr):
        return getattr(obj, attr)
    if isinstance(obj, dict) and attr in obj:
        return obj[attr]
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


def get_run_summary(conn: sqlite3.Connection, sync_id: str) -> dict[str, dict[str, int]]:
    """Return per-table counts of records added and updated in the run with the given sync_id."""
    summary: dict[str, dict[str, int]] = {}
    for table in (
        "tenants",
        "firewalls",
        "licenses",
        "license_subscriptions",
        "alerts",
        "alert_details",
        "firmware_upgrades",
        "firmware_versions",
    ):
        added_cur = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE sync_id = ? AND first_sync = last_sync",
            (sync_id,),
        )
        updated_cur = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE sync_id = ? AND (first_sync IS NULL OR first_sync != last_sync)",
            (sync_id,),
        )
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
            sync_id TEXT
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
            sync_id TEXT
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
            sync_id TEXT
        );
    """)
    _migrate_sync_columns(conn)
    _ensure_sync_columns(conn)
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
    ):
        cur = conn.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in cur.fetchall()}
        for col_spec in columns:
            name = col_spec.split()[0]
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_spec}")
                logger.debug("Added column %s to %s", name, table)


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def upsert_tenant(
    conn: sqlite3.Connection,
    tenant: Any,
    *,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Insert or replace a tenant. Accepts central.classes.Tenant or dict-like."""
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
        _get(tenant, "id") or "unknown",
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
    )
    conn.execute(
        """
        INSERT INTO tenants (
            id, show_as, name, data_geography, data_region, billing_type,
            partner_id, organization_id, api_host, status, contact_json,
            external_ids_json, products_json, updated_at,
            first_sync, last_sync, sync_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            sync_id = excluded.sync_id
        """,
        row,
    )


def upsert_firewall(
    conn: sqlite3.Connection,
    firewall: Any,
    *,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Insert or replace a firewall. Accepts central.firewalls.classes.Firewall."""
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
    )
    conn.execute(
        """
        INSERT INTO firewalls (
            id, tenant_id, serial_number, group_id, group_name, hostname, name,
            external_ipv4_addresses_json, firmware_version, model,
            managing_status, reporting_status, connected, suspended,
            state_changed_at, capabilities_json, geo_latitude, geo_longitude,
            created_at, updated_at,
            first_sync, last_sync, sync_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            sync_id = excluded.sync_id
        """,
        row,
    )


def upsert_license(
    conn: sqlite3.Connection,
    license_obj: Any,
    *,
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

    conn.execute(
        """
        INSERT INTO licenses (
            serial_number, tenant_id, partner_id, organization_id,
            model, model_type, last_seen_at,
            first_sync, last_sync, sync_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(serial_number) DO UPDATE SET
            tenant_id = excluded.tenant_id,
            partner_id = excluded.partner_id,
            organization_id = excluded.organization_id,
            model = excluded.model,
            model_type = excluded.model_type,
            last_seen_at = excluded.last_seen_at,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id
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
        ),
    )

    subs = getattr(license_obj, "licenses", None) or []
    for sub in subs:
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
                first_sync, last_sync, sync_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                sync_id = excluded.sync_id
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
            ),
        )


def upsert_alert(
    conn: sqlite3.Connection,
    alert: Any,
    *,
    tenant_id: Optional[str] = None,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Insert or replace an alert. Accepts central.alerts.classes.Alert or dict-like."""
    aid = _get(alert, "id") or "unknown"
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
    )
    conn.execute(
        """
        INSERT INTO alerts (
            id, tenant_id, category, description, group_key, product,
            raised_at, severity, type, allowed_actions_json,
            managed_agent_json, person_json, tenant_ref_json,
            first_sync, last_sync, sync_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            sync_id = excluded.sync_id
        """,
        row,
    )


def upsert_alert_detail(
    conn: sqlite3.Connection,
    alert: Any,
    *,
    tenant_id: Optional[str] = None,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Insert or replace a row in alert_details (full alert from get_alert). Same shape as alerts."""
    aid = _get(alert, "id") or "unknown"
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
    )
    conn.execute(
        """
        INSERT INTO alert_details (
            id, tenant_id, category, description, group_key, product,
            raised_at, severity, type, allowed_actions_json,
            managed_agent_json, person_json, tenant_ref_json,
            first_sync, last_sync, sync_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            sync_id = excluded.sync_id
        """,
        row,
    )


def upsert_firmware_upgrade(
    conn: sqlite3.Connection,
    upgrade: Any,
    *,
    tenant_id: str,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Insert or replace a firewall firmware upgrade row. Accepts FirewallUpgrade."""
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
    )
    conn.execute(
        """
        INSERT INTO firmware_upgrades (
            firewall_id, tenant_id, serial_number, current_version,
            upgrade_to_versions_json,
            first_sync, last_sync, sync_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(firewall_id) DO UPDATE SET
            tenant_id = excluded.tenant_id,
            serial_number = excluded.serial_number,
            current_version = excluded.current_version,
            upgrade_to_versions_json = excluded.upgrade_to_versions_json,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id
        """,
        row,
    )


def upsert_firmware_version(
    conn: sqlite3.Connection,
    fw_version: Any,
    *,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Insert or replace a firmware version (release notes). Accepts FirmwareVersion."""
    row = (
        fw_version.version,
        getattr(fw_version, "size", None),
        _to_json(getattr(fw_version, "bugs", None)),
        _to_json(getattr(fw_version, "news", None)),
        run_timestamp,
        run_timestamp,
        update_id,
    )
    conn.execute(
        """
        INSERT INTO firmware_versions (
            version, size, bugs_json, news_json,
            first_sync, last_sync, sync_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(version) DO UPDATE SET
            size = excluded.size,
            bugs_json = excluded.bugs_json,
            news_json = excluded.news_json,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id
        """,
        row,
    )
