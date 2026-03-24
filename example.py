"""
Example CLI demonstrating Sophos Central API usage (firewalls, groups, licenses, firmware).
Run from the project root with credentials in `.env` or `credentials.env`.
"""
from __future__ import annotations
import argparse
from datetime import datetime
import logging
import os
from typing import List
from dotenv import dotenv_values

from central.firewalls.firmware.classes import FirmwareUpgrade
from central.logging_config import configure_logging
from central.firewalls.licenses.classes import License
from central.session import CentralSession
from central.firewalls.methods import get_firewalls
from central.firewalls.groups.methods import get_firewall_groups
from central.firewalls.classes import Firewall
from central.firewalls.groups.classes import Group
from central.firewalls.licenses import get_licenses
from central.firewalls.firmware.methods import firmware_upgrade_check


# Default log level when not overridden by CLI or LOG_LEVEL env
DEFAULT_LOG_LEVEL = "INFO"

LOG_LEVEL_CHOICES = ("DEBUG", "INFO", "WARNING", "ERROR")

logger = logging.getLogger(__name__)


def print_group_summary(groups: List[Group]):
    for group in groups:
        print(
            f"Firewall group: '{group.name}' firewalls: {group.firewalls.total} {group.parentGroup}"
        )


def get_creds() -> dict:
    creds = None
    if os.path.exists("./credentials.env"):
        logger.info("Loading credentials from credentials.env")
        creds = dotenv_values("./credentials.env")
    elif os.path.exists("./.env"):
        logger.info("Loading credentials from .env")
        creds = dotenv_values("./.env")

    if (
        not creds
        or "CENTRAL-CLIENT-ID" not in creds
        or "CENTRAL-CLIENT-SECRET" not in creds
    ):
        logger.error(
            "No valid credentials found (CENTRAL-CLIENT-ID and CENTRAL-CLIENT-SECRET required)"
        )
        raise Exception("No credentials found")

    logger.debug("Credentials loaded successfully")
    return creds


def print_firewall_summary(firewalls: List[Firewall]):
    managing_status = 0
    pending_approval = 0
    reporting_status = 0
    connected = 0
    suspended = 0

    if not firewalls or len(firewalls) == 0:
        logger.info("No firewalls found")
        return

    for firewall in firewalls:
        if "approved" in firewall.status.managingStatus:
            managing_status += 1
        elif (
            "pending" in firewall.status.managingStatus
            or "pending" in firewall.status.reportingStatus
        ):
            pending_approval += 1
        if "approved" in firewall.status.reportingStatus:
            reporting_status += 1
        if firewall.status.connected:
            connected += 1
        if firewall.status.suspended:
            suspended += 1
        # print(f"Firewall: {firewall.hostname} ({firewall.serialNumber}) ver: {firewall.firmwareVersion} model: {firewall.model} status: {firewall.status}")
    print(
        (
            f"Firewall counts: {len(firewalls)}; "
            f"Manage Enabled: {managing_status}; "
            f"Report Enabled: {reporting_status}; "
            f"Pending Approval: {pending_approval}; "
            f"Connected: {connected}; "
            f"Sync Suspended: {suspended}."
        )
    )


def print_license_summary(licenses: List[License]):
    print("Licenses:")
    for license in licenses:
        result = f"Serial No.: {license.serialNumber} - model: {license.model} has ({len(license.licenses)} licenses)\n"
        for sub in license.licenses:
            # sub = Subscription(**subscription)

            result += (
                f"    License: {sub.type} for serial:{sub.licenseIdentifier}\n"
                f"    product: {sub.product}\n"
                f"    valid from: {sub.startDate} to: {sub.endDate}\n"
                f"    perpetual: {sub.perpetual}\n"
                f"    quantity: {sub.quantity}\n"
                f"    unlimited: {sub.unlimited}\n"
                f"    usage: {sub.usage if sub.usage else 'N/A'}\n"
                "    -----\n"
            )
        print(result)


def parse_args():
    parser = argparse.ArgumentParser(description="Sophos Central API example client")
    parser.add_argument(
        "-l",
        "--log-level",
        choices=LOG_LEVEL_CHOICES,
        default=None,
        metavar="LEVEL",
        help=f"Override log level for this run (default: {DEFAULT_LOG_LEVEL}, or LOG_LEVEL env)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    # CLI override > LOG_LEVEL env > default
    log_level = args.log_level or os.environ.get("LOG_LEVEL", DEFAULT_LOG_LEVEL)
    configure_logging(level=log_level)
    creds = get_creds()

    client_id = creds["CENTRAL-CLIENT-ID"]
    client_secret = creds["CENTRAL-CLIENT-SECRET"]
    logger.info("Authenticating with client ID: %s", client_id)
    central = CentralSession(client_id, client_secret)
    auth_result = central.authenticate()
    if not auth_result.success:
        print(f"Unable to authenticate successfully: {auth_result}")
        logger.error("Authentication failed: %s", auth_result.message)
        return

    logger.info(
        "Authenticated to %s api account '%s'",
        central.whoami.idType,
        central.whoami.id,
    )
    logger.debug("Global URL: %s", central.whoami.global_url())
    logger.debug("Data Region URL: %s", central.whoami.data_region_url())

    print(f"central.whoami: {central.whoami}")

    if central.whoami.idType == "partner":
        logger.info("Fetching tenants...")
        tenants = central.get_tenants()
        logger.info("Found %d tenants; fetching firewalls per tenant", len(tenants))
        print(f"Partner tenants: {len(tenants)}")
        logger.info("Fetching licenses for partner")
        licenses = get_licenses(central, partner_id=central.whoami.id)
        print(f"    Partner licenses: {len(licenses)}")
        print("-- Tenant details --")

        for tenant in tenants:
            print(
                f"Tenant: {tenant.name} ({tenant.id}) {tenant.dataRegion} {tenant.billingType} apiHost: {tenant.apiHost}"
            )

            firewalls = get_firewalls(
                central,
                tenant_id=tenant.id,
                url_base=tenant.apiHost,
            )
            if firewalls.success:
                print(f"    Firewalls: {len(firewalls)}")
            else:
                print(f"    Firewalls: {firewalls.message}")

            licenses = get_licenses(
                central,
                tenant_id=tenant.id,  # , partner_id=central.whoami.id
            )
            if licenses.success:
                print(f"    Licenses: {len(licenses)}")
            else:
                print(f"    Licenses: {licenses.message}")

            fw_ids = [fw.id for fw in firewalls]
            firmware_upgrades = firmware_upgrade_check(
                central, fw_ids, tenant_id=tenant.id, url_base=tenant.apiHost
            )
            if firmware_upgrades.success:
                upgrades = firmware_upgrades.list_available_upgrades()
                print(f"    Firmware upgrades: {len(upgrades)}")
                for fw in upgrades:
                    print(
                        f"    {fw.serialNumber} {fw.firmwareVersion} {fw.upgradeToVersion}"
                    )

            else:
                print(f"    Firmware upgrades: {firmware_upgrades.message}")

    else:
        firewalls = get_firewalls(central)
        print_firewall_summary(firewalls)
        groups = get_firewall_groups(central)
        logger.info("Found %d firewall groups", len(groups))
        for group in groups:
            logger.debug("Group: %s (%s)", group.name, group.id)

        result = get_licenses(central)
        print_license_summary(result)

        fw_ids = [fw.id for fw in firewalls]
        firmware_upgrades = firmware_upgrade_check(
            central,
            fw_ids,
            tenant_id=central.whoami.id,
            url_base=central.whoami.data_region_url(),
        )
        if firmware_upgrades.success:
            print(
                f"    Firmware upgrades: {len(firmware_upgrades.list_available_upgrades())}"
            )
            for fw in firmware_upgrades.firewalls:
                print(
                    f"    {fw.serialNumber} {fw.firmwareVersion} {fw.upgradeToVersion}"
                )

        else:
            print(f"    Firmware upgrades: {firmware_upgrades.message}")


def test():
    upgrade = FirmwareUpgrade(
        id="123", upgradeToVersion="23.0.0.1234", upgradeAt=datetime.now()
    )
    print(upgrade.__dict__())


if __name__ == "__main__":
    # test()
    main()
