#!/usr/bin/env python3
"""
Companion script: sync tenants, firewalls, and licenses from Sophos Central to a local SQLite DB.
Updates existing records and inserts new ones. Uses credentials from credentials.env or .env.
"""

from __future__ import annotations

import argparse
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import dotenv_values

from central.logging_config import configure_logging
from central.session import CentralSession
from central.classes import ReturnState
from central.db import (
    DEFAULT_DB_PATH,
    get_connection,
    get_run_summary,
    init_schema,
    upsert_tenant,
    upsert_firewall,
    upsert_license,
)
from central.firewalls.methods import get_firewalls
from central.firewalls.licenses import get_licenses

DEFAULT_LOG_LEVEL = "INFO"
LOG_LEVEL_CHOICES = ("TRACE", "DEBUG", "INFO", "WARNING", "ERROR")

logger = logging.getLogger(__name__)


def get_creds() -> dict:
    if os.path.exists("./credentials.env"):
        logger.info("Loading credentials from credentials.env")
        creds = dotenv_values("./credentials.env")
    elif os.path.exists("./.env"):
        logger.info("Loading credentials from .env")
        creds = dotenv_values("./.env")
    else:
        creds = None

    if (
        not creds
        or "CENTRAL-CLIENT-ID" not in creds
        or "CENTRAL-CLIENT-SECRET" not in creds
    ):
        logger.error(
            "No valid credentials found (CENTRAL-CLIENT-ID and CENTRAL-CLIENT-SECRET required)"
        )
        raise ValueError("No credentials found")
    return creds


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_tenant_record(
    conn,
    whoami_id: str,
    name: str = "Current tenant",
    *,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Ensure a tenant row exists for single-tenant mode (e.g. from whoami)."""
    conn.execute(
        """
        INSERT INTO tenants (
            id, show_as, name, updated_at,
            added_timestamp, updated_timestamp, update_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            updated_at = excluded.updated_at,
            updated_timestamp = excluded.updated_timestamp,
            update_id = excluded.update_id
        """,
        (whoami_id, name, name, _now_utc(), run_timestamp, run_timestamp, update_id),
    )


def sync_partner(
    conn,
    central: CentralSession,
    *,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Sync all tenants and per-tenant firewalls and licenses; then partner-level licenses."""
    tenants_result = central.get_tenants()
    if isinstance(tenants_result, ReturnState) and not tenants_result.success:
        logger.warning("Could not fetch tenants: %s", tenants_result.message)
        tenants = []
    else:
        tenants = list(tenants_result)

    logger.info("Syncing %d tenants", len(tenants))
    for tenant in tenants:
        upsert_tenant(conn, tenant, update_id=update_id, run_timestamp=run_timestamp)
        logger.debug("Tenant upserted: %s (%s)", tenant.name, tenant.id)

        firewalls_result = get_firewalls(
            central,
            tenant_id=tenant.id,
            url_base=tenant.apiHost,
        )
        if isinstance(firewalls_result, ReturnState) and not firewalls_result.success:
            logger.warning("Firewalls for tenant %s: %s", tenant.id, firewalls_result.message)
        else:
            firewalls = firewalls_result
            for fw in firewalls:
                upsert_firewall(conn, fw, update_id=update_id, run_timestamp=run_timestamp)
            logger.info("Tenant %s: %d firewalls synced", tenant.name, len(firewalls))

        licenses_result = get_licenses(central, tenant_id=tenant.id)
        if isinstance(licenses_result, ReturnState) and not licenses_result.success:
            logger.warning("Licenses for tenant %s: %s", tenant.id, licenses_result.message)
        else:
            for lic in licenses_result:
                upsert_license(
                    conn,
                    lic,
                    tenant_id=tenant.id,
                    update_id=update_id,
                    run_timestamp=run_timestamp,
                )
            logger.info("Tenant %s: %d license records synced", tenant.name, len(licenses_result))

    # Partner-level licenses
    partner_licenses_result = get_licenses(central, partner_id=central.whoami.id)
    if isinstance(partner_licenses_result, ReturnState) and not partner_licenses_result.success:
        logger.warning("Partner licenses: %s", partner_licenses_result.message)
    else:
        for lic in partner_licenses_result:
            upsert_license(
                conn,
                lic,
                partner_id=central.whoami.id,
                update_id=update_id,
                run_timestamp=run_timestamp,
            )
        logger.info("Partner-level licenses: %d synced", len(partner_licenses_result))


def sync_tenant(
    conn,
    central: CentralSession,
    *,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Sync current tenant context: one tenant row, firewalls, licenses."""
    whoami = central.whoami
    ensure_tenant_record(
        conn,
        whoami.id,
        name=whoami.id,
        update_id=update_id,
        run_timestamp=run_timestamp,
    )

    firewalls_result = get_firewalls(central)
    if isinstance(firewalls_result, ReturnState) and not firewalls_result.success:
        logger.warning("Firewalls: %s", firewalls_result.message)
    else:
        for fw in firewalls_result:
            upsert_firewall(conn, fw, update_id=update_id, run_timestamp=run_timestamp)
        logger.info("Firewalls synced: %d", len(firewalls_result))

    licenses_result = get_licenses(central)
    if isinstance(licenses_result, ReturnState) and not licenses_result.success:
        logger.warning("Licenses: %s", licenses_result.message)
    else:
        for lic in licenses_result:
            upsert_license(
                conn,
                lic,
                tenant_id=whoami.id,
                update_id=update_id,
                run_timestamp=run_timestamp,
            )
        logger.info("Licenses synced: %d", len(licenses_result))


def parse_args():
    p = argparse.ArgumentParser(
        description="Sync Sophos Central tenants, firewalls, and licenses to SQLite"
    )
    p.add_argument(
        "-l", "--log-level",
        choices=LOG_LEVEL_CHOICES,
        default=None,
        help=f"Log level (default: {DEFAULT_LOG_LEVEL})",
    )
    p.add_argument(
        "-d", "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"SQLite database path (default: {DEFAULT_DB_PATH})",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    log_level = args.log_level or os.environ.get("LOG_LEVEL", DEFAULT_LOG_LEVEL)
    configure_logging(level=log_level)

    creds = get_creds()
    client_id = creds["CENTRAL-CLIENT-ID"]
    client_secret = creds["CENTRAL-CLIENT-SECRET"]

    logger.info("Authenticating with Sophos Central")
    central = CentralSession(client_id, client_secret)
    auth_result = central.authenticate()
    if not auth_result.success:
        logger.error("Authentication failed: %s", auth_result.message)
        raise SystemExit(1)

    logger.info(
        "Authenticated as %s '%s'",
        central.whoami.idType,
        central.whoami.id,
    )

    update_id = uuid.uuid4().hex
    run_timestamp = _now_utc()

    conn = get_connection(args.db)
    try:
        init_schema(conn)
        if central.whoami.idType == "partner":
            sync_partner(
                conn,
                central,
                update_id=update_id,
                run_timestamp=run_timestamp,
            )
        else:
            sync_tenant(
                conn,
                central,
                update_id=update_id,
                run_timestamp=run_timestamp,
            )
        conn.commit()
        summary = get_run_summary(conn, update_id)
        logger.info("Sync completed. Database: %s", args.db.resolve())
        total_added = sum(s["added"] for s in summary.values())
        total_updated = sum(s["updated"] for s in summary.values())
        print(f"update_id: {update_id}")
        print("Summary:")
        for table, counts in summary.items():
            print(f"  {table}: {counts['added']} added, {counts['updated']} updated")
        print(f"  Total: {total_added} added, {total_updated} updated")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
