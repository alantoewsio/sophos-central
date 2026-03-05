#!/usr/bin/env python3
"""
Companion script: export tenants, firewalls, and licenses from Sophos Central to CSV files.
Uses the same data sources as sync_to_db but writes to CSV instead of SQLite.
Uses credentials from credentials.env or .env.
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from dotenv import dotenv_values

from central.logging_config import configure_logging
from central.session import CentralSession
from central.classes import ReturnState
from central.db import _get, _get_nested, _to_json
from central.firewalls.methods import get_firewalls
from central.firewalls.licenses import get_licenses

DEFAULT_LOG_LEVEL = "INFO"
LOG_LEVEL_CHOICES = ("TRACE", "DEBUG", "INFO", "WARNING", "ERROR")
DEFAULT_OUTPUT_DIR = Path("export")

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


def tenant_to_row(tenant: Any) -> dict[str, Any]:
    """Flatten a tenant (or dict) to a row suitable for CSV."""
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

    return {
        "id": _get(tenant, "id") or "unknown",
        "show_as": _get(tenant, "showAs"),
        "name": _get(tenant, "name") or "Unknown",
        "data_geography": _get(tenant, "dataGeography"),
        "data_region": _get(tenant, "dataRegion"),
        "billing_type": _get(tenant, "billingType"),
        "partner_id": _get_nested(tenant, "partner", "id"),
        "organization_id": _get_nested(tenant, "organization", "id"),
        "api_host": _get(tenant, "apiHost"),
        "status": _get(tenant, "status"),
        "contact_json": contact_json or "",
        "external_ids_json": _to_json(external_ids) or "",
        "products_json": _to_json(products) or "",
        "updated_at": _now_utc(),
    }


def firewall_to_row(firewall: Any) -> dict[str, Any]:
    """Flatten a firewall to a row suitable for CSV."""
    tenant = getattr(firewall, "tenant", None)
    tenant_id = getattr(tenant, "id", None) if tenant else (tenant or {}).get("id")
    group = getattr(firewall, "group", None)
    group_id = getattr(group, "id", None) if group else None
    group_name = getattr(group, "name", None) if group else None
    status = getattr(firewall, "status", None)
    geo = getattr(firewall, "geoLocation", None)

    return {
        "id": getattr(firewall, "id", None),
        "tenant_id": tenant_id,
        "serial_number": getattr(firewall, "serialNumber", None),
        "group_id": group_id,
        "group_name": group_name,
        "hostname": getattr(firewall, "hostname", None),
        "name": getattr(firewall, "name", None),
        "external_ipv4_addresses_json": _to_json(getattr(firewall, "externalIpv4Addresses", None)) or "",
        "firmware_version": getattr(firewall, "firmwareVersion", None),
        "model": getattr(firewall, "model", None),
        "managing_status": getattr(status, "managingStatus", None) if status else None,
        "reporting_status": getattr(status, "reportingStatus", None) if status else None,
        "connected": 1 if (status and getattr(status, "connected", False)) else 0,
        "suspended": 1 if (status and getattr(status, "suspended", False)) else 0,
        "state_changed_at": getattr(firewall, "stateChangedAt", None),
        "capabilities_json": _to_json(getattr(firewall, "capabilities", None)) or "",
        "geo_latitude": getattr(geo, "latitude", None) if geo else None,
        "geo_longitude": getattr(geo, "longitude", None) if geo else None,
        "created_at": getattr(firewall, "createdAt", None),
        "updated_at": getattr(firewall, "updatedAt", None),
        "synced_at": _now_utc(),
    }


def license_to_row(license_obj: Any, tenant_id: Optional[str] = None, partner_id: Optional[str] = None) -> dict[str, Any]:
    """Flatten a license header to a row suitable for CSV."""
    tenant_id = tenant_id or (getattr(license_obj.tenant, "id", None) if getattr(license_obj, "tenant", None) else None)
    partner_id = partner_id or (getattr(license_obj.partner, "id", None) if getattr(license_obj, "partner", None) else None)
    org_id = getattr(license_obj.organization, "id", None) if getattr(license_obj, "organization", None) else None

    return {
        "serial_number": license_obj.serialNumber,
        "tenant_id": tenant_id,
        "partner_id": partner_id,
        "organization_id": org_id,
        "model": license_obj.model,
        "model_type": getattr(license_obj, "modelType", None),
        "last_seen_at": getattr(license_obj, "lastSeenAt", None),
        "synced_at": _now_utc(),
    }


def subscription_to_row(sub: Any, serial_number: str) -> dict[str, Any]:
    """Flatten a license subscription to a row suitable for CSV."""
    product = getattr(sub, "product", None)
    product_code = getattr(product, "code", None) if product else None
    product_name = getattr(product, "name", None) if product else None
    usage = getattr(sub, "usage", None)
    usage_current = getattr(usage, "current", None) if usage else None
    usage_count = getattr(usage_current, "count", None) if usage_current else None
    usage_date = getattr(usage_current, "date", None) if usage_current else None
    if usage_date is not None and hasattr(usage_date, "isoformat"):
        usage_date = usage_date.isoformat()

    return {
        "id": sub.id,
        "serial_number": serial_number,
        "license_identifier": getattr(sub, "licenseIdentifier", None),
        "product_code": product_code,
        "product_name": product_name,
        "start_date": getattr(sub, "startDate", None),
        "end_date": getattr(sub, "endDate", None),
        "perpetual": 1 if getattr(sub, "perpetual", False) else 0,
        "type": getattr(sub, "type", None),
        "quantity": getattr(sub, "quantity", None),
        "usage_count": usage_count,
        "usage_date": usage_date,
        "unlimited": 1 if getattr(sub, "unlimited", False) else 0,
        "synced_at": _now_utc(),
    }


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    """Write rows to a CSV file with header."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: ("" if v is None else v) for k, v in row.items()})


TENANT_FIELDS = [
    "id", "show_as", "name", "data_geography", "data_region", "billing_type",
    "partner_id", "organization_id", "api_host", "status",
    "contact_json", "external_ids_json", "products_json", "updated_at",
]

FIREWALL_FIELDS = [
    "id", "tenant_id", "serial_number", "group_id", "group_name", "hostname", "name",
    "external_ipv4_addresses_json", "firmware_version", "model",
    "managing_status", "reporting_status", "connected", "suspended",
    "state_changed_at", "capabilities_json", "geo_latitude", "geo_longitude",
    "created_at", "updated_at", "synced_at",
]

LICENSE_FIELDS = [
    "serial_number", "tenant_id", "partner_id", "organization_id",
    "model", "model_type", "last_seen_at", "synced_at",
]

SUBSCRIPTION_FIELDS = [
    "id", "serial_number", "license_identifier", "product_code", "product_name",
    "start_date", "end_date", "perpetual", "type", "quantity",
    "usage_count", "usage_date", "unlimited", "synced_at",
]


def export_partner(out_dir: Path, central: CentralSession) -> None:
    """Export all tenants and per-tenant firewalls and licenses; then partner-level licenses."""
    tenants_result = central.get_tenants()
    if isinstance(tenants_result, ReturnState) and not tenants_result.success:
        logger.warning("Could not fetch tenants: %s", tenants_result.message)
        tenants = []
    else:
        tenants = list(tenants_result)

    logger.info("Exporting %d tenants", len(tenants))

    tenant_rows = [tenant_to_row(t) for t in tenants]
    write_csv(out_dir / "tenants.csv", TENANT_FIELDS, tenant_rows)

    all_firewalls: list[dict[str, Any]] = []
    all_licenses: list[dict[str, Any]] = []
    all_subscriptions: list[dict[str, Any]] = []

    for tenant in tenants:
        firewalls_result = get_firewalls(
            central,
            tenant_id=tenant.id,
            url_base=tenant.apiHost,
        )
        if isinstance(firewalls_result, ReturnState) and not firewalls_result.success:
            logger.warning("Firewalls for tenant %s: %s", tenant.id, firewalls_result.message)
        else:
            for fw in firewalls_result:
                all_firewalls.append(firewall_to_row(fw))
            logger.info("Tenant %s: %d firewalls exported", tenant.name, len(firewalls_result))

        licenses_result = get_licenses(central, tenant_id=tenant.id)
        if isinstance(licenses_result, ReturnState) and not licenses_result.success:
            logger.warning("Licenses for tenant %s: %s", tenant.id, licenses_result.message)
        else:
            for lic in licenses_result:
                all_licenses.append(license_to_row(lic, tenant_id=tenant.id))
                for sub in getattr(lic, "licenses", None) or []:
                    all_subscriptions.append(subscription_to_row(sub, lic.serialNumber))
            logger.info("Tenant %s: %d license records exported", tenant.name, len(licenses_result))

    write_csv(out_dir / "firewalls.csv", FIREWALL_FIELDS, all_firewalls)

    # Partner-level licenses
    partner_licenses_result = get_licenses(central, partner_id=central.whoami.id)
    if isinstance(partner_licenses_result, ReturnState) and not partner_licenses_result.success:
        logger.warning("Partner licenses: %s", partner_licenses_result.message)
    else:
        for lic in partner_licenses_result:
            all_licenses.append(license_to_row(lic, partner_id=central.whoami.id))
            for sub in getattr(lic, "licenses", None) or []:
                all_subscriptions.append(subscription_to_row(sub, lic.serialNumber))
        logger.info("Partner-level licenses: %d exported", len(partner_licenses_result))

    write_csv(out_dir / "licenses.csv", LICENSE_FIELDS, all_licenses)
    write_csv(out_dir / "license_subscriptions.csv", SUBSCRIPTION_FIELDS, all_subscriptions)


def export_tenant(out_dir: Path, central: CentralSession) -> None:
    """Export current tenant context: one tenant row, firewalls, licenses."""
    whoami = central.whoami
    tenant_placeholder = {
        "id": whoami.id,
        "showAs": whoami.id,
        "name": whoami.id,
        "dataGeography": None,
        "dataRegion": None,
        "billingType": None,
        "partner": None,
        "organization": None,
        "apiHost": None,
        "status": None,
        "contact": None,
        "externalIds": None,
        "products": None,
    }
    tenant_rows = [tenant_to_row(tenant_placeholder)]
    write_csv(out_dir / "tenants.csv", TENANT_FIELDS, tenant_rows)

    firewalls_result = get_firewalls(central)
    if isinstance(firewalls_result, ReturnState) and not firewalls_result.success:
        logger.warning("Firewalls: %s", firewalls_result.message)
        firewall_rows = []
    else:
        firewall_rows = [firewall_to_row(fw) for fw in firewalls_result]
        logger.info("Firewalls exported: %d", len(firewalls_result))
    write_csv(out_dir / "firewalls.csv", FIREWALL_FIELDS, firewall_rows)

    licenses_result = get_licenses(central)
    if isinstance(licenses_result, ReturnState) and not licenses_result.success:
        logger.warning("Licenses: %s", licenses_result.message)
        license_rows = []
        subscription_rows = []
    else:
        license_rows = []
        subscription_rows = []
        for lic in licenses_result:
            license_rows.append(license_to_row(lic, tenant_id=whoami.id))
            for sub in getattr(lic, "licenses", None) or []:
                subscription_rows.append(subscription_to_row(sub, lic.serialNumber))
        logger.info("Licenses exported: %d", len(licenses_result))
    write_csv(out_dir / "licenses.csv", LICENSE_FIELDS, license_rows)
    write_csv(out_dir / "license_subscriptions.csv", SUBSCRIPTION_FIELDS, subscription_rows)


def parse_args():
    p = argparse.ArgumentParser(
        description="Export Sophos Central tenants, firewalls, and licenses to CSV files"
    )
    p.add_argument(
        "-l", "--log-level",
        choices=LOG_LEVEL_CHOICES,
        default=None,
        help=f"Log level (default: {DEFAULT_LOG_LEVEL})",
    )
    p.add_argument(
        "-o", "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for CSV files (default: {DEFAULT_OUTPUT_DIR})",
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

    out_dir = args.output_dir.resolve()
    if central.whoami.idType == "partner":
        export_partner(out_dir, central)
    else:
        export_tenant(out_dir, central)

    logger.info("Export completed. Output directory: %s", out_dir)


if __name__ == "__main__":
    main()
