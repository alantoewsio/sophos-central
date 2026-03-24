#!/usr/bin/env python3
"""
Companion script: sync tenants, firewalls, firewall groups, group sync status, optional MDR threat-feed
snapshots, licenses, alerts, and firmware update info from Sophos Central to a local SQLite DB.
Updates existing records and inserts new ones. Uses credentials from credentials.env or .env.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sqlite3
import sys
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import dotenv_values
from openpyxl import Workbook

from central.logging_config import configure_logging
from central.session import CentralSession
from central.classes import ReturnState
from central.db import (
    DEFAULT_DB_PATH,
    get_connection,
    get_latest_alert_raised_at,
    get_new_alert_ids,
    get_run_summary,
    init_schema,
    upsert_tenant,
    upsert_firewall,
    upsert_license,
    upsert_alert,
    upsert_alert_detail,
    upsert_firmware_upgrade,
    upsert_firmware_version,
    upsert_firewall_group,
    upsert_firewall_group_sync_status,
    upsert_mdr_threat_feed_sync,
)
from central.firewalls.methods import get_firewalls
from central.firewalls.licenses import get_licenses
from central.alerts.methods import get_alert, get_alerts
from central.firewalls.firmware.methods import firmware_upgrade_check
from central.firewalls.groups.methods import (
    get_firewall_group_sync_status,
    get_firewall_groups,
)
from central.firewalls.mdr.methods import get_firewall_transaction, get_mdr_threat_feed

DEFAULT_LOG_LEVEL = "INFO"
LOG_LEVEL_CHOICES = ("DEBUG", "INFO", "WARNING", "ERROR")

logger = logging.getLogger(__name__)


class CentralSyncAuthError(Exception):
    """Raised when Sophos Central authentication fails during a credentials DB sync."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass(frozen=True, slots=True)
class CredentialsSyncResult:
    """Outcome of one credentials sync run (see ``sync_client_credentials_to_database``)."""

    sync_id: str
    summary: dict[str, dict[str, int]]
    elapsed_by_table: dict[str, float]
    total_elapsed: float


def get_creds() -> dict:
    """Load credentials from default files: credentials.env or .env."""
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


def get_creds_from_env_file(path: str | Path) -> dict:
    """Load credentials from a specific .env file. Raises ValueError if missing/invalid."""
    path = Path(path)
    if not path.exists():
        raise ValueError(f"Env file not found: {path}")
    logger.info("Loading credentials from %s", path)
    creds = dotenv_values(str(path))
    if (
        not creds
        or "CENTRAL-CLIENT-ID" not in creds
        or "CENTRAL-CLIENT-SECRET" not in creds
    ):
        raise ValueError(
            f"Invalid credentials in {path}: CENTRAL-CLIENT-ID and CENTRAL-CLIENT-SECRET required"
        )
    return creds


def _cred_sources_from_args(args) -> list[tuple[str, str]]:
    """Return a list of (client_id, client_secret) from CLI args. Uses defaults if none given."""
    sources: list[tuple[str, str]] = []

    if getattr(args, "client_id", None) and getattr(args, "client_secret", None):
        sources.append((args.client_id.strip(), args.client_secret.strip()))

    for env_path in getattr(args, "env", None) or []:
        creds = get_creds_from_env_file(env_path)
        sources.append(
            (creds["CENTRAL-CLIENT-ID"].strip(), creds["CENTRAL-CLIENT-SECRET"])
        )

    if not sources:
        creds = get_creds()
        sources.append(
            (creds["CENTRAL-CLIENT-ID"].strip(), creds["CENTRAL-CLIENT-SECRET"])
        )
    return sources


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sync_mdr_threat_feed_for_firewall(
    conn: sqlite3.Connection,
    central: CentralSession,
    *,
    firewall_id: str,
    tenant_id: str,
    url_base: str,
    client_id: str,
    update_id: str,
    run_timestamp: str,
    max_polls: int = 12,
    sleep_fn=time.sleep,
) -> None:
    """Request MDR threat feed and poll the transaction until finished or max_polls."""
    kick = get_mdr_threat_feed(
        central,
        firewall_id,
        url_base=url_base,
        tenant_id=tenant_id,
    )
    if not kick.success or kick.value is None:
        upsert_mdr_threat_feed_sync(
            conn,
            firewall_id=firewall_id,
            tenant_id=tenant_id,
            client_id=client_id,
            update_id=update_id,
            run_timestamp=run_timestamp,
            poll_status="request_failed",
            detail_message=kick.message or "get_mdr_threat_feed failed",
        )
        return
    data = kick.value.data or {}
    tx_id = data.get("transactionId")
    if not tx_id:
        upsert_mdr_threat_feed_sync(
            conn,
            firewall_id=firewall_id,
            tenant_id=tenant_id,
            client_id=client_id,
            update_id=update_id,
            run_timestamp=run_timestamp,
            poll_status="no_transaction_id",
            detail_message="Response missing transactionId",
        )
        return

    last_body: dict | None = None
    for _ in range(max_polls):
        tr = get_firewall_transaction(
            central,
            firewall_id,
            str(tx_id),
            url_base=url_base,
            tenant_id=tenant_id,
        )
        if not tr.success or tr.value is None:
            upsert_mdr_threat_feed_sync(
                conn,
                firewall_id=firewall_id,
                tenant_id=tenant_id,
                client_id=client_id,
                update_id=update_id,
                run_timestamp=run_timestamp,
                transaction_id=str(tx_id),
                poll_status="poll_failed",
                detail_message=tr.message or "get_firewall_transaction failed",
            )
            return
        last_body = tr.value.data or {}
        if last_body.get("status") == "finished":
            upsert_mdr_threat_feed_sync(
                conn,
                firewall_id=firewall_id,
                tenant_id=tenant_id,
                client_id=client_id,
                update_id=update_id,
                run_timestamp=run_timestamp,
                transaction_id=str(tx_id),
                poll_status="finished",
                transaction_status=last_body.get("status"),
                transaction_result=last_body.get("result"),
                response_json=json.dumps(last_body, default=str),
            )
            return
        sleep_fn(1.0)

    upsert_mdr_threat_feed_sync(
        conn,
        firewall_id=firewall_id,
        tenant_id=tenant_id,
        client_id=client_id,
        update_id=update_id,
        run_timestamp=run_timestamp,
        transaction_id=str(tx_id),
        poll_status="timeout",
        transaction_status=(last_body or {}).get("status"),
        transaction_result=(last_body or {}).get("result"),
        response_json=json.dumps(last_body, default=str) if last_body else None,
    )


def _format_duration(seconds: float) -> str:
    """Format elapsed seconds for display (e.g. 1.23s or 450ms)."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    return f"{seconds:.2f}s"


def _try_enable_windows_console_vt() -> None:
    """Enable ANSI escape processing on Windows conhost (needed for clear-line progress)."""
    if sys.platform != "win32":
        return
    if not sys.stdout.isatty():
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        h = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            return
        vt = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if mode.value & vt:
            return
        kernel32.SetConsoleMode(h, mode.value | vt)
    except Exception:
        return


def _progress_erase_prefix() -> str:
    """Return prefix to move to start of line and clear it (or plain CR if disabled)."""
    if os.environ.get("NO_COLOR") or os.environ.get("TERM", "").lower() == "dumb":
        return "\r"
    return "\r\x1b[2K"


class SyncProgress:
    """Single-line progress bar and step message for CLI. Clears before summary.
    Width follows the terminal so the line does not wrap (wrap breaks \\r updates).
    Uses CSI clear-line when supported so shorter messages do not leave stale text.
    """

    BAR_WIDTH = 20
    # Hard cap for very wide terminals; real width is min(this, columns - 1)
    MAX_LINE = 79

    def __init__(self) -> None:
        self._visible = sys.stdout.isatty()
        if self._visible:
            _try_enable_windows_console_vt()
        self._total = 0
        self._current = 0
        self._message = ""

    def set_total(self, n: int) -> None:
        self._total = max(0, n)

    def _terminal_width(self) -> int:
        """Usable width for one logical line (avoid wrap so \\r stays on one visual row)."""
        try:
            cols = shutil.get_terminal_size().columns
        except OSError:
            cols = self.MAX_LINE + 1
        inner = max(1, cols - 1)
        return min(self.MAX_LINE, inner)

    def update(self, message: str, current: int | None = None) -> None:
        if not self._visible:
            return
        if current is not None:
            self._current = current
        self._message = message
        self._render()

    def _render(self) -> None:
        max_line = self._terminal_width()
        if self._total > 0:
            filled = min(
                self.BAR_WIDTH - 2,  # leave room for ">"
                int(self.BAR_WIDTH * self._current / self._total),
            )
            bar = "[" + "=" * filled + ">" + " " * (self.BAR_WIDTH - 3 - filled) + "]"
            frac = f" {self._current}/{self._total}"
        else:
            bar = "[" + " " * self.BAR_WIDTH + "]"
            frac = ""
        # Bar + fraction is fixed width; truncate message so whole line fits terminal
        prefix_len = len(bar) + len(frac) + 2  # "  "
        max_msg = max(1, max_line - prefix_len)
        if len(self._message) > max_msg:
            msg = self._message[: max_msg - 3] + "..."
        else:
            msg = self._message
        line = bar + frac + "  " + msg
        if len(line) > max_line:
            line = line[:max_line]
        erase = _progress_erase_prefix()
        if erase == "\r":
            line = line.ljust(max_line)
        sys.stdout.write(erase + line)
        sys.stdout.flush()

    def clear(self) -> None:
        if not self._visible:
            return
        erase = _progress_erase_prefix()
        if erase == "\r":
            sys.stdout.write("\r" + " " * self._terminal_width() + "\r")
        else:
            sys.stdout.write(erase)
        sys.stdout.flush()


def _from_time_after(latest_raised_at: str) -> str | None:
    """Return an ISO 8601 datetime 1 second after latest_raised_at, or None on parse error."""
    try:
        ts = latest_raised_at.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        next_dt = dt + timedelta(seconds=1)
        return next_dt.isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError):
        logger.warning(
            "Could not parse latest alert raised_at %r, syncing all alerts",
            latest_raised_at,
        )
        return None


def ensure_tenant_record(
    conn,
    whoami_id: str,
    name: str = "Current tenant",
    *,
    client_id: str,
    update_id: str,
    run_timestamp: str,
) -> None:
    """Ensure a tenant row exists for single-tenant mode (e.g. from whoami)."""
    conn.execute(
        """
        INSERT INTO tenants (
            id, show_as, name, updated_at,
            first_sync, last_sync, sync_id, client_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            updated_at = excluded.updated_at,
            last_sync = excluded.last_sync,
            sync_id = excluded.sync_id,
            client_id = excluded.client_id
        """,
        (
            whoami_id,
            name,
            name,
            _now_utc(),
            run_timestamp,
            run_timestamp,
            update_id,
            client_id,
        ),
    )


SUMMARY_TABLES = (
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
)

# Pre-built SELECT * queries per table (table names are fixed; no user input).
_SELECT_ALL_QUERIES = {
    "tenants": "SELECT * FROM tenants",
    "firewalls": "SELECT * FROM firewalls",
    "licenses": "SELECT * FROM licenses",
    "license_subscriptions": "SELECT * FROM license_subscriptions",
    "alerts": "SELECT * FROM alerts",
    "alert_details": "SELECT * FROM alert_details",
    "firmware_upgrades": "SELECT * FROM firmware_upgrades",
    "firmware_versions": "SELECT * FROM firmware_versions",
    "firewall_groups": "SELECT * FROM firewall_groups",
    "firewall_group_sync_status": "SELECT * FROM firewall_group_sync_status",
    "mdr_threat_feed_sync": "SELECT * FROM mdr_threat_feed_sync",
}

# Excel sheet names must be <= 31 chars; our table names fit
_XLSX_SHEET_NAME_MAX = 31


def export_db_to_xlsx(conn, out_path: Path) -> None:
    """Write all SUMMARY_TABLES to an xlsx workbook, one table per sheet."""
    wb = Workbook()
    first = True
    for table in SUMMARY_TABLES:
        cur = conn.execute(_SELECT_ALL_QUERIES[table])
        rows = cur.fetchall()
        col_names = [d[0] for d in cur.description]
        sheet_name = table[:_XLSX_SHEET_NAME_MAX]
        if first:
            ws = wb.active
            ws.title = sheet_name
            first = False
        else:
            ws = wb.create_sheet(title=sheet_name)
        ws.append(col_names)
        for row in rows:
            ws.append(list(row))
    wb.save(out_path)
    logger.info("Exported all tables to %s", out_path)


def sync_partner(
    conn,
    central: CentralSession,
    *,
    client_id: str,
    update_id: str,
    run_timestamp: str,
    elapsed_by_table: dict[str, float] | None = None,
    progress: SyncProgress | None = None,
    sync_mdr: bool = False,
) -> None:
    """Sync all tenants and per-tenant firewalls and licenses; then partner-level licenses."""
    if elapsed_by_table is None:
        elapsed_by_table = {}
    tenants_result = central.get_tenants()
    if isinstance(tenants_result, ReturnState) and not tenants_result.success:
        logger.warning("Could not fetch tenants: %s", tenants_result.message)
        tenants = []
    else:
        tenants = list(tenants_result)

    steps_per_tenant = 8 + (1 if sync_mdr else 0)
    total_steps = len(tenants) * steps_per_tenant + 1
    if progress is not None:
        progress.set_total(total_steps)

    logger.info("Syncing %d tenants", len(tenants))
    step = 0
    for tenant in tenants:
        if progress is not None:
            progress.update(f"Tenant {tenant.name!r}: tenant record", step)
        t0 = time.perf_counter()
        upsert_tenant(
            conn,
            tenant,
            client_id=client_id,
            update_id=update_id,
            run_timestamp=run_timestamp,
        )
        elapsed_by_table["tenants"] = elapsed_by_table.get("tenants", 0) + (
            time.perf_counter() - t0
        )
        logger.debug("Tenant upserted: %s (%s)", tenant.name, tenant.id)
        step += 1

        if progress is not None:
            progress.update(f"Tenant {tenant.name!r}: firewalls", step)
        t0 = time.perf_counter()
        firewalls: list = []
        firewalls_result = get_firewalls(
            central,
            tenant_id=tenant.id,
            url_base=tenant.apiHost,
        )
        if isinstance(firewalls_result, ReturnState) and not firewalls_result.success:
            logger.warning(
                "Firewalls for tenant %s: %s", tenant.id, firewalls_result.message
            )
        else:
            firewalls = list(firewalls_result)
            for fw in firewalls:
                upsert_firewall(
                    conn,
                    fw,
                    client_id=client_id,
                    update_id=update_id,
                    run_timestamp=run_timestamp,
                )
        elapsed = time.perf_counter() - t0
        elapsed_by_table["firewalls"] = elapsed_by_table.get("firewalls", 0) + elapsed
        logger.info(
            "Tenant %s: %d firewalls synced (%s)",
            tenant.name,
            len(firewalls),
            _format_duration(elapsed),
        )
        step += 1

        if progress is not None:
            progress.update(f"Tenant {tenant.name!r}: licenses", step)
        t0 = time.perf_counter()
        licenses_result = get_licenses(
            central, tenant_id=tenant.id, url_base=tenant.apiHost
        )
        if isinstance(licenses_result, ReturnState) and not licenses_result.success:
            logger.warning(
                "Licenses for tenant %s: %s", tenant.id, licenses_result.message
            )
        else:
            for lic in licenses_result:
                upsert_license(
                    conn,
                    lic,
                    client_id=client_id,
                    tenant_id=tenant.id,
                    update_id=update_id,
                    run_timestamp=run_timestamp,
                )
        elapsed = time.perf_counter() - t0
        elapsed_by_table["licenses"] = elapsed_by_table.get("licenses", 0) + elapsed
        elapsed_by_table["license_subscriptions"] = (
            elapsed_by_table.get("license_subscriptions", 0) + elapsed
        )
        logger.info(
            "Tenant %s: %d license records synced (%s)",
            tenant.name,
            len(licenses_result) if not isinstance(licenses_result, ReturnState) else 0,
            _format_duration(elapsed),
        )
        step += 1

        if progress is not None:
            progress.update(f"Tenant {tenant.name!r}: alerts", step)
        # Alerts for this tenant (firewall + other only; incremental from latest if any)
        from_time = None
        latest_raised = get_latest_alert_raised_at(conn, tenant.id)
        if latest_raised:
            from_time = _from_time_after(latest_raised)
            logger.debug("Tenant %s: syncing alerts from %s", tenant.id, from_time)
        t0 = time.perf_counter()
        alerts_result = get_alerts(
            central,
            tenant_id=tenant.id,
            url_base=tenant.apiHost,
            product=["firewall", "other"],
            from_time=from_time,
        )
        if isinstance(alerts_result, ReturnState) and not alerts_result.success:
            logger.warning("Alerts for tenant %s: %s", tenant.id, alerts_result.message)
        else:
            for alert in alerts_result:
                upsert_alert(
                    conn,
                    alert,
                    client_id=client_id,
                    tenant_id=tenant.id,
                    update_id=update_id,
                    run_timestamp=run_timestamp,
                )
        elapsed = time.perf_counter() - t0
        elapsed_by_table["alerts"] = elapsed_by_table.get("alerts", 0) + elapsed
        logger.info(
            "Tenant %s: %d alerts synced (%s)",
            tenant.name,
            len(alerts_result) if not isinstance(alerts_result, ReturnState) else 0,
            _format_duration(elapsed),
        )
        step += 1

        # Fetch and upsert full details for new alerts only
        new_alert_ids = get_new_alert_ids(conn, update_id, tenant.id)
        if progress is not None and not new_alert_ids:
            progress.update(f"Tenant {tenant.name!r}: alert details", step)
        if new_alert_ids:
            n_alert_details = len(new_alert_ids)
            t0_details = time.perf_counter()
            for i, aid in enumerate(new_alert_ids, start=1):
                if progress is not None:
                    progress.update(
                        f"Tenant {tenant.name!r}: alert details ({i}/{n_alert_details})",
                        step,
                    )
                detail_result = get_alert(
                    central,
                    aid,
                    tenant_id=tenant.id,
                    url_base=tenant.apiHost,
                )
                if not isinstance(detail_result, ReturnState) and detail_result:
                    upsert_alert_detail(
                        conn,
                        detail_result,
                        client_id=client_id,
                        tenant_id=tenant.id,
                        update_id=update_id,
                        run_timestamp=run_timestamp,
                    )
            elapsed_by_table["alert_details"] = elapsed_by_table.get(
                "alert_details", 0
            ) + (time.perf_counter() - t0_details)
            logger.info(
                "Tenant %s: %d alert details synced",
                tenant.name,
                len(new_alert_ids),
            )
        step += 1

        if progress is not None:
            progress.update(f"Tenant {tenant.name!r}: firmware", step)
        # Firmware upgrade info for this tenant's firewalls
        if firewalls:
            t0 = time.perf_counter()
            fw_ids = [fw.id for fw in firewalls]
            firmware_result = firmware_upgrade_check(
                central,
                fw_ids,
                url_base=tenant.apiHost,
                tenant_id=tenant.id,
            )
            if isinstance(firmware_result, ReturnState) and not firmware_result.success:
                logger.warning(
                    "Firmware upgrade check for tenant %s: %s",
                    tenant.id,
                    firmware_result.message,
                )
            else:
                for upgrade in firmware_result.firewalls:
                    upsert_firmware_upgrade(
                        conn,
                        upgrade,
                        client_id=client_id,
                        tenant_id=tenant.id,
                        update_id=update_id,
                        run_timestamp=run_timestamp,
                    )
                for fw_ver in firmware_result.firmwareVersions:
                    upsert_firmware_version(
                        conn,
                        fw_ver,
                        client_id=client_id,
                        update_id=update_id,
                        run_timestamp=run_timestamp,
                    )
            elapsed = time.perf_counter() - t0
            elapsed_by_table["firmware_upgrades"] = (
                elapsed_by_table.get("firmware_upgrades", 0) + elapsed
            )
            elapsed_by_table["firmware_versions"] = (
                elapsed_by_table.get("firmware_versions", 0) + elapsed
            )
            logger.info(
                "Tenant %s: %d firmware upgrade rows, %d firmware versions synced (%s)",
                tenant.name,
                len(firmware_result.firewalls)
                if not isinstance(firmware_result, ReturnState)
                else 0,
                len(firmware_result.firmwareVersions)
                if not isinstance(firmware_result, ReturnState)
                else 0,
                _format_duration(elapsed),
            )
        step += 1

        if progress is not None:
            progress.update(f"Tenant {tenant.name!r}: firewall groups", step)
        t0 = time.perf_counter()
        groups_result = get_firewall_groups(
            central,
            tenant_id=tenant.id,
            url_base=tenant.apiHost,
        )
        groups_list: list = []
        if isinstance(groups_result, ReturnState) and not groups_result.success:
            logger.warning(
                "Firewall groups for tenant %s: %s",
                tenant.id,
                groups_result.message,
            )
        else:
            groups_list = list(groups_result)
            for grp in groups_list:
                upsert_firewall_group(
                    conn,
                    grp,
                    tenant_id=tenant.id,
                    client_id=client_id,
                    update_id=update_id,
                    run_timestamp=run_timestamp,
                )
        elapsed = time.perf_counter() - t0
        elapsed_by_table["firewall_groups"] = (
            elapsed_by_table.get("firewall_groups", 0) + elapsed
        )
        logger.info(
            "Tenant %s: %d firewall groups synced (%s)",
            tenant.name,
            len(groups_list),
            _format_duration(elapsed),
        )
        step += 1

        if progress is not None:
            progress.update(
                f"Tenant {tenant.name!r}: firewall group sync status", step
            )
        t0 = time.perf_counter()
        n_sync_rows = 0
        for grp in groups_list:
            sync_res = get_firewall_group_sync_status(
                central,
                grp.id,
                tenant_id=tenant.id,
                url_base=tenant.apiHost,
            )
            if isinstance(sync_res, ReturnState) and not sync_res.success:
                logger.warning(
                    "Group sync status %s / %s: %s",
                    tenant.id,
                    grp.id,
                    sync_res.message,
                )
                continue
            for row in sync_res:
                upsert_firewall_group_sync_status(
                    conn,
                    group_id=grp.id,
                    firewall_id=row.firewall.id,
                    tenant_id=tenant.id,
                    status=row.status,
                    last_updated_at=row.lastUpdatedAt,
                    client_id=client_id,
                    update_id=update_id,
                    run_timestamp=run_timestamp,
                )
                n_sync_rows += 1
        elapsed = time.perf_counter() - t0
        elapsed_by_table["firewall_group_sync_status"] = (
            elapsed_by_table.get("firewall_group_sync_status", 0) + elapsed
        )
        logger.info(
            "Tenant %s: %d group sync status rows (%s)",
            tenant.name,
            n_sync_rows,
            _format_duration(elapsed),
        )
        step += 1

        if sync_mdr and firewalls:
            if progress is not None:
                progress.update(f"Tenant {tenant.name!r}: MDR threat feed", step)
            t0 = time.perf_counter()
            for fw in firewalls:
                _sync_mdr_threat_feed_for_firewall(
                    conn,
                    central,
                    firewall_id=fw.id,
                    tenant_id=tenant.id,
                    url_base=tenant.apiHost,
                    client_id=client_id,
                    update_id=update_id,
                    run_timestamp=run_timestamp,
                )
            elapsed = time.perf_counter() - t0
            elapsed_by_table["mdr_threat_feed_sync"] = (
                elapsed_by_table.get("mdr_threat_feed_sync", 0) + elapsed
            )
            logger.info(
                "Tenant %s: MDR threat feed polled for %d firewalls (%s)",
                tenant.name,
                len(firewalls),
                _format_duration(elapsed),
            )
            step += 1

    if progress is not None:
        progress.update("Partner-level licenses", step)
    # Partner-level licenses
    t0 = time.perf_counter()
    partner_licenses_result = get_licenses(central, partner_id=central.whoami.id)
    if (
        isinstance(partner_licenses_result, ReturnState)
        and not partner_licenses_result.success
    ):
        logger.warning("Partner licenses: %s", partner_licenses_result.message)
    else:
        for lic in partner_licenses_result:
            upsert_license(
                conn,
                lic,
                client_id=client_id,
                partner_id=central.whoami.id,
                update_id=update_id,
                run_timestamp=run_timestamp,
            )
    elapsed = time.perf_counter() - t0
    elapsed_by_table["licenses"] = elapsed_by_table.get("licenses", 0) + elapsed
    elapsed_by_table["license_subscriptions"] = (
        elapsed_by_table.get("license_subscriptions", 0) + elapsed
    )
    logger.info(
        "Partner-level licenses: %d synced (%s)",
        len(partner_licenses_result)
        if not isinstance(partner_licenses_result, ReturnState)
        else 0,
        _format_duration(elapsed),
    )


def sync_tenant(
    conn,
    central: CentralSession,
    *,
    client_id: str,
    update_id: str,
    run_timestamp: str,
    elapsed_by_table: dict[str, float] | None = None,
    progress: SyncProgress | None = None,
    sync_mdr: bool = False,
) -> None:
    """Sync current tenant context: one tenant row, firewalls, licenses, groups, optional MDR."""
    if elapsed_by_table is None:
        elapsed_by_table = {}
    if progress is not None:
        progress.set_total(8 + (1 if sync_mdr else 0))
    whoami = central.whoami
    url_base = whoami.data_region_url()
    if progress is not None:
        progress.update("Tenant record", 0)
    t0 = time.perf_counter()
    ensure_tenant_record(
        conn,
        whoami.id,
        name=whoami.id,
        client_id=client_id,
        update_id=update_id,
        run_timestamp=run_timestamp,
    )
    elapsed_by_table["tenants"] = time.perf_counter() - t0

    if progress is not None:
        progress.update("Firewalls", 1)
    t0 = time.perf_counter()
    firewalls_result = get_firewalls(
        central, tenant_id=whoami.id, url_base=url_base
    )
    firewalls_list = []
    if isinstance(firewalls_result, ReturnState) and not firewalls_result.success:
        logger.warning("Firewalls: %s", firewalls_result.message)
    else:
        firewalls_list = list(firewalls_result)
        for fw in firewalls_list:
            upsert_firewall(
                conn,
                fw,
                client_id=client_id,
                update_id=update_id,
                run_timestamp=run_timestamp,
            )
    elapsed = time.perf_counter() - t0
    elapsed_by_table["firewalls"] = elapsed_by_table.get("firewalls", 0) + elapsed
    logger.info(
        "Firewalls synced: %d (%s)", len(firewalls_list), _format_duration(elapsed)
    )

    if progress is not None:
        progress.update("Licenses", 2)
    t0 = time.perf_counter()
    licenses_result = get_licenses(
        central, tenant_id=whoami.id, url_base=url_base
    )
    if isinstance(licenses_result, ReturnState) and not licenses_result.success:
        logger.warning("Licenses: %s", licenses_result.message)
    else:
        for lic in licenses_result:
            upsert_license(
                conn,
                lic,
                client_id=client_id,
                tenant_id=whoami.id,
                update_id=update_id,
                run_timestamp=run_timestamp,
            )
    elapsed = time.perf_counter() - t0
    elapsed_by_table["licenses"] = elapsed_by_table.get("licenses", 0) + elapsed
    elapsed_by_table["license_subscriptions"] = (
        elapsed_by_table.get("license_subscriptions", 0) + elapsed
    )
    logger.info(
        "Licenses synced: %d (%s)",
        len(licenses_result) if not isinstance(licenses_result, ReturnState) else 0,
        _format_duration(elapsed),
    )

    if progress is not None:
        progress.update("Alerts", 3)
    # Alerts for current tenant (firewall + other only; incremental from latest if any)
    from_time = None
    latest_raised = get_latest_alert_raised_at(conn, whoami.id)
    if latest_raised:
        from_time = _from_time_after(latest_raised)
        logger.debug("Syncing alerts from %s", from_time)
    t0 = time.perf_counter()
    alerts_result = get_alerts(
        central,
        tenant_id=whoami.id,
        url_base=url_base,
        product=["firewall", "other"],
        from_time=from_time,
    )
    if isinstance(alerts_result, ReturnState) and not alerts_result.success:
        logger.warning("Alerts: %s", alerts_result.message)
    else:
        for alert in alerts_result:
            upsert_alert(
                conn,
                alert,
                client_id=client_id,
                tenant_id=whoami.id,
                update_id=update_id,
                run_timestamp=run_timestamp,
            )
    elapsed = time.perf_counter() - t0
    elapsed_by_table["alerts"] = elapsed_by_table.get("alerts", 0) + elapsed
    logger.info(
        "Alerts synced: %d (%s)",
        len(alerts_result) if not isinstance(alerts_result, ReturnState) else 0,
        _format_duration(elapsed),
    )

    # Fetch and upsert full details for new alerts only
    new_alert_ids = get_new_alert_ids(conn, update_id, whoami.id)
    if progress is not None and not new_alert_ids:
        progress.update("Alert details", 4)
    if new_alert_ids:
        n_alert_details = len(new_alert_ids)
        t0_details = time.perf_counter()
        for i, aid in enumerate(new_alert_ids, start=1):
            if progress is not None:
                progress.update(
                    f"Alert details ({i}/{n_alert_details})",
                    4,
                )
            detail_result = get_alert(
                central, aid, tenant_id=whoami.id, url_base=url_base
            )
            if not isinstance(detail_result, ReturnState) and detail_result:
                upsert_alert_detail(
                    conn,
                    detail_result,
                    client_id=client_id,
                    tenant_id=whoami.id,
                    update_id=update_id,
                    run_timestamp=run_timestamp,
                )
        elapsed_by_table["alert_details"] = elapsed_by_table.get("alert_details", 0) + (
            time.perf_counter() - t0_details
        )
        logger.info("Alert details synced: %d", len(new_alert_ids))

    if progress is not None:
        progress.update("Firmware", 5)
    # Firmware upgrade info for current tenant's firewalls
    if firewalls_list:
        t0 = time.perf_counter()
        fw_ids = [fw.id for fw in firewalls_list]
        firmware_result = firmware_upgrade_check(
            central, fw_ids, tenant_id=whoami.id, url_base=url_base
        )
        if isinstance(firmware_result, ReturnState) and not firmware_result.success:
            logger.warning("Firmware upgrade check: %s", firmware_result.message)
        else:
            for upgrade in firmware_result.firewalls:
                upsert_firmware_upgrade(
                    conn,
                    upgrade,
                    client_id=client_id,
                    tenant_id=whoami.id,
                    update_id=update_id,
                    run_timestamp=run_timestamp,
                )
            for fw_ver in firmware_result.firmwareVersions:
                upsert_firmware_version(
                    conn,
                    fw_ver,
                    client_id=client_id,
                    update_id=update_id,
                    run_timestamp=run_timestamp,
                )
        elapsed = time.perf_counter() - t0
        elapsed_by_table["firmware_upgrades"] = (
            elapsed_by_table.get("firmware_upgrades", 0) + elapsed
        )
        elapsed_by_table["firmware_versions"] = (
            elapsed_by_table.get("firmware_versions", 0) + elapsed
        )
        logger.info(
            "Firmware: %d upgrade rows, %d versions synced (%s)",
            len(firmware_result.firewalls)
            if not isinstance(firmware_result, ReturnState)
            else 0,
            len(firmware_result.firmwareVersions)
            if not isinstance(firmware_result, ReturnState)
            else 0,
            _format_duration(elapsed),
        )

    if progress is not None:
        progress.update("Firewall groups", 6)
    t0 = time.perf_counter()
    groups_result = get_firewall_groups(
        central,
        tenant_id=whoami.id,
        url_base=url_base,
    )
    groups_list: list = []
    if isinstance(groups_result, ReturnState) and not groups_result.success:
        logger.warning("Firewall groups: %s", groups_result.message)
    else:
        groups_list = list(groups_result)
        for grp in groups_list:
            upsert_firewall_group(
                conn,
                grp,
                tenant_id=whoami.id,
                client_id=client_id,
                update_id=update_id,
                run_timestamp=run_timestamp,
            )
    elapsed = time.perf_counter() - t0
    elapsed_by_table["firewall_groups"] = (
        elapsed_by_table.get("firewall_groups", 0) + elapsed
    )
    logger.info(
        "Firewall groups synced: %d (%s)",
        len(groups_list),
        _format_duration(elapsed),
    )

    if progress is not None:
        progress.update("Firewall group sync status", 7)
    t0 = time.perf_counter()
    n_sync_rows = 0
    for grp in groups_list:
        sync_res = get_firewall_group_sync_status(
            central,
            grp.id,
            tenant_id=whoami.id,
            url_base=url_base,
        )
        if isinstance(sync_res, ReturnState) and not sync_res.success:
            logger.warning(
                "Group sync status for %s: %s", grp.id, sync_res.message
            )
            continue
        for row in sync_res:
            upsert_firewall_group_sync_status(
                conn,
                group_id=grp.id,
                firewall_id=row.firewall.id,
                tenant_id=whoami.id,
                status=row.status,
                last_updated_at=row.lastUpdatedAt,
                client_id=client_id,
                update_id=update_id,
                run_timestamp=run_timestamp,
            )
            n_sync_rows += 1
    elapsed = time.perf_counter() - t0
    elapsed_by_table["firewall_group_sync_status"] = (
        elapsed_by_table.get("firewall_group_sync_status", 0) + elapsed
    )
    logger.info(
        "Group sync status rows: %d (%s)",
        n_sync_rows,
        _format_duration(elapsed),
    )

    if sync_mdr and firewalls_list:
        if progress is not None:
            progress.update("MDR threat feed", 8)
        t0 = time.perf_counter()
        for fw in firewalls_list:
            _sync_mdr_threat_feed_for_firewall(
                conn,
                central,
                firewall_id=fw.id,
                tenant_id=whoami.id,
                url_base=url_base,
                client_id=client_id,
                update_id=update_id,
                run_timestamp=run_timestamp,
            )
        elapsed = time.perf_counter() - t0
        elapsed_by_table["mdr_threat_feed_sync"] = (
            elapsed_by_table.get("mdr_threat_feed_sync", 0) + elapsed
        )
        logger.info(
            "MDR threat feed polled for %d firewalls (%s)",
            len(firewalls_list),
            _format_duration(elapsed),
        )


@contextmanager
def _quiet_sync_cli_loggers(quiet: bool):
    """When quiet, swallow central.* logs (including this module) so nothing reaches root/stderr."""
    if not quiet:
        yield
        return
    targets = (logging.getLogger("central"),)
    saved: list[tuple[logging.Logger, list[logging.Handler], bool]] = []
    for lg in targets:
        saved.append((lg, lg.handlers[:], lg.propagate))
        lg.handlers = [logging.NullHandler()]
        lg.propagate = False
    try:
        yield
    finally:
        for lg, handlers, prop in saved:
            lg.handlers = handlers
            lg.propagate = prop


def sync_client_credentials_to_database(
    conn: sqlite3.Connection,
    client_id: str,
    client_secret: str,
    *,
    quiet: bool = True,
    progress: SyncProgress | None = None,
    sync_mdr: bool = False,
) -> CredentialsSyncResult:
    """
    Sync one Sophos Central API credential (partner or tenant) into an open SQLite connection.

    Call ``init_schema(conn)`` at least once on ``conn`` before the first sync.

    * **quiet=True** (default): no terminal output (no progress bar, no log lines to CLI).
      Use this when embedding from another app that already holds ``conn``.
    * **quiet=False**: same logging/progress behavior as the CLI (configure logging first;
      pass a ``SyncProgress`` instance for a TTY progress bar).

    Returns a :class:`CredentialsSyncResult`. Commits the connection on success.
    Raises :class:`CentralSyncAuthError` if authentication fails.
    """
    client_id, client_secret = client_id.strip(), client_secret.strip()
    use_progress = None if quiet else progress

    with _quiet_sync_cli_loggers(quiet):
        if not quiet:
            logger.info("Authenticating with Sophos Central")
        central = CentralSession(client_id, client_secret)
        auth_result = central.authenticate()
        if not auth_result.success:
            raise CentralSyncAuthError(auth_result.message or "Authentication failed")
        if not quiet:
            logger.info(
                "Authenticated as %s '%s'",
                central.whoami.idType,
                central.whoami.id,
            )

        update_id = uuid.uuid4().hex
        run_timestamp = _now_utc()
        sync_start = time.perf_counter()
        elapsed_by_table: dict[str, float] = {t: 0.0 for t in SUMMARY_TABLES}

        if central.whoami.idType == "partner":
            sync_partner(
                conn,
                central,
                client_id=client_id,
                update_id=update_id,
                run_timestamp=run_timestamp,
                elapsed_by_table=elapsed_by_table,
                progress=use_progress,
                sync_mdr=sync_mdr,
            )
        else:
            sync_tenant(
                conn,
                central,
                client_id=client_id,
                update_id=update_id,
                run_timestamp=run_timestamp,
                elapsed_by_table=elapsed_by_table,
                progress=use_progress,
                sync_mdr=sync_mdr,
            )

        total_elapsed = time.perf_counter() - sync_start
        conn.commit()
        summary = get_run_summary(conn, update_id)

    return CredentialsSyncResult(
        sync_id=update_id,
        summary=summary,
        elapsed_by_table=elapsed_by_table,
        total_elapsed=total_elapsed,
    )


def parse_args():
    p = argparse.ArgumentParser(
        prog="central-sync-to-db",
        description="Sync Sophos Central tenants, firewalls, groups, licenses, alerts, and firmware info to SQLite",
    )
    p.add_argument(
        "-l",
        "--log-level",
        choices=LOG_LEVEL_CHOICES,
        default=None,
        help=f"Log level (default: {DEFAULT_LOG_LEVEL})",
    )
    p.add_argument(
        "-d",
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"SQLite database path (default: {DEFAULT_DB_PATH})",
    )
    p.add_argument(
        "--client-id",
        dest="client_id",
        metavar="ID",
        default=None,
        help="Sophos Central client ID (use with --client-secret for inline creds)",
    )
    p.add_argument(
        "--client-secret",
        dest="client_secret",
        metavar="SECRET",
        default=None,
        help="Sophos Central client secret (use with --client-id for inline creds)",
    )
    p.add_argument(
        "-e",
        "--env",
        dest="env",
        action="append",
        type=Path,
        metavar="FILE",
        default=None,
        help="Path to .env file with CENTRAL-CLIENT-ID and CENTRAL-CLIENT-SECRET (repeat for multiple)",
    )
    p.add_argument(
        "-x",
        "--export-xlsx",
        dest="export_xlsx",
        type=Path,
        metavar="FILE",
        default=None,
        nargs="?",
        const="",  # trigger when flag present with no path
        help="Export all DB tables to an xlsx workbook (one sheet per table). Optional path (default: <db-stem>.xlsx beside the DB).",
    )
    p.add_argument(
        "--mdr",
        action="store_true",
        help=(
            "After firewall groups, request MDR threat feed per firewall and poll transactions "
            "(slow; can add minutes per firewall)."
        ),
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    log_level = args.log_level or os.environ.get("LOG_LEVEL", DEFAULT_LOG_LEVEL)
    configure_logging(level=log_level)

    # Require both or neither for inline creds
    if (args.client_id is None) != (args.client_secret is None):
        logger.error(
            "Provide both --client-id and --client-secret for inline credentials"
        )
        raise SystemExit(1)

    try:
        sources = _cred_sources_from_args(args)
    except ValueError as e:
        logger.error("%s", e)
        raise SystemExit(1)

    conn = get_connection(args.db)
    progress = SyncProgress()
    try:
        init_schema(conn)
        for idx, (client_id, client_secret) in enumerate(sources, start=1):
            run_label = f"creds {idx}/{len(sources)}"
            if len(sources) > 1:
                logger.info("Sync run %s", run_label)
            try:
                result = sync_client_credentials_to_database(
                    conn,
                    client_id,
                    client_secret,
                    quiet=False,
                    progress=progress,
                    sync_mdr=args.mdr,
                )
            except CentralSyncAuthError as e:
                logger.error("Authentication failed: %s", e.message)
                raise SystemExit(1)

            logger.info("Sync completed. Database: %s", args.db.resolve())
            total_added = sum(s["added"] for s in result.summary.values())
            total_updated = sum(s["updated"] for s in result.summary.values())
            progress.clear()
            if len(sources) > 1:
                print(f"--- {run_label} ---")
            print(f"sync_id: {result.sync_id}")
            print("Summary:")
            for table, counts in result.summary.items():
                duration = _format_duration(result.elapsed_by_table.get(table, 0))
                print(
                    f"  {table}: {counts['added']} added, {counts['updated']} updated ({duration})"
                )
            print(
                f"  Total: {total_added} added, {total_updated} updated (sync: {_format_duration(result.total_elapsed)})"
            )
        if args.export_xlsx is not None:
            xlsx_path = (
                Path(args.export_xlsx)
                if args.export_xlsx
                else args.db.with_suffix(".xlsx")
            )
            export_db_to_xlsx(conn, xlsx_path)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
