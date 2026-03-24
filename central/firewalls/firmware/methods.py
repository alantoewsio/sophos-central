import logging
from datetime import datetime, timezone
from typing import List, Union
from central.session import CentralSession
from central.classes import ReturnState
from central.firewalls.firmware.classes import (
    FirewallUpgradeInfo,
    FirewallUpgrade,
    FirmwareVersion,
    FirmwareUpgrade,
)

logger = logging.getLogger(__name__)


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewalls/actions/firmware-upgrade-check/post
def firmware_upgrade_check(
    central: CentralSession,
    firewall_ids: List[str],
    url_base: str = None,
    tenant_id: str = None,
) -> FirewallUpgradeInfo | ReturnState:
    """Check if a firmware upgrade is available for a firewall.
    Args:
        central: CentralSession object
        firewall_ids: List[str], the IDs of the firewalls to check if a firmware upgrade is available for
        url_base: str, optional, the base URL of the API
        tenant_id: str, optional, the ID of the tenant containing the target firewalls"""

    if len(firewall_ids) == 0:
        return ReturnState(
            success=False,
            value=[],
            message="No firewall IDs to look up",
        )
    payload = {
        "firewalls": firewall_ids,
    }
    # /firewall/v1/firewalls/actions/firmware-upgrade-check
    response = central.post(
        "/firewall/v1/firewalls/actions/firmware-upgrade-check",
        url_base=url_base,
        tenant_id=tenant_id,
        payload=payload,
    )
    if not response.success:
        logger.error("get_licenses failed: %s", getattr(response, "message", response))
        return ReturnState(
            success=False,
            value=response,
            message=f"error: received status code {response.value.status_code}",
        )
    updates = FirewallUpgradeInfo(firewalls=[], firmwareVersions=[])

    response_value = response.value
    if not response_value.success:
        return ReturnState(
            success=False,
            value=response_value,
            message=f"error: received status code {response_value.status_code}",
        )

    results = response_value.data
    for firewall in results["firewalls"]:
        if firewall:
            updates.firewalls.append(FirewallUpgrade(**firewall))

    for firmware in results["firmwareVersions"]:
        if firmware:
            updates.firmwareVersions.append(FirmwareVersion(**firmware))

    logger.info(
        f"get_licenses returned {len(updates.firewalls)} firewall records and {len(updates.firmwareVersions)} version release notes"
    )
    return updates


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewalls/actions/firmware-upgrade/post
def upgrade_firmware(
    central: CentralSession,
    upgrades: Union[FirmwareUpgrade, List[FirmwareUpgrade]],
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Schedule a firmware upgrade for one or more firewalls.

    POST /firewall/v1/firewalls/actions/firmware-upgrade
    Request body: ``{"firewalls": [ upgrade objects ]}`` per OpenAPI.

    Args:
        central: CentralSession object
        upgrades: FirmwareUpgrade or list of FirmwareUpgrade (id, upgradeToVersion, optional upgradeAt)
        url_base: Optional base URL of the API
        tenant_id: Optional tenant ID containing the target firewalls

    Returns:
        ReturnState with success, message, and value=CentralResponse (201 = scheduled successfully).
    """
    if isinstance(upgrades, FirmwareUpgrade):
        upgrades = [upgrades]
    if not upgrades:
        return ReturnState(
            success=False,
            value=[],
            message="No firmware upgrades to schedule",
        )

    def _format_upgrade_at(dt: datetime) -> str:
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc)
        return (
            dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond // 1000:03d}Z"
        )

    def _upgrade_to_payload(u: FirmwareUpgrade) -> dict:
        payload = {
            "id": u.id,
            "upgradeToVersion": u.upgradeToVersion,
        }
        if u.upgradeAt is not None:
            payload["upgradeAt"] = _format_upgrade_at(u.upgradeAt)
        return payload

    payload = {"firewalls": [_upgrade_to_payload(u) for u in upgrades]}

    logger.info(
        "upgrade_firmware count=%s ids=%s",
        len(upgrades),
        [u.id for u in upgrades],
    )
    response = central.post(
        "/firewall/v1/firewalls/actions/firmware-upgrade",
        url_base=url_base,
        tenant_id=tenant_id,
        payload=payload,
    )
    if not response.success:
        logger.error(
            "upgrade_firmware failed: %s",
            getattr(response.value, "status_code", response.message),
        )
        return ReturnState(
            success=False,
            value=response.value,
            message=response.message or "upgrade_firmware request failed",
        )
    central_response = response.value
    status_codes = {
        201: "Firmware upgrade scheduled successfully.",
        400: "Invalid request",
        401: "Authentication required",
        403: "Authorization required",
        404: "Firewall not found",
        500: "Unexpected error",
    }
    return ReturnState(
        success=central_response.success,
        message=status_codes.get(central_response.status_code, "Unexpected response"),
        value=central_response,
    )


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewalls/actions/firmware-upgrade/delete
def cancel_firmware_upgrade(
    central: CentralSession,
    firewall_ids: List[str],
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Cancel a scheduled firmware upgrade for one or more firewalls.

    DELETE /firewall/v1/firewalls/actions/firmware-upgrade
    Request body: list of firewall IDs to cancel the scheduled upgrade for.

    Args:
        central: CentralSession object
        firewall_ids: List of firewall IDs whose scheduled upgrade should be cancelled
        url_base: Optional base URL of the API
        tenant_id: Optional tenant ID containing the target firewalls

    Returns:
        ReturnState with success, message, and value=CentralResponse (201 = cancelled successfully).
    """
    if not firewall_ids:
        return ReturnState(
            success=False,
            value=[],
            message="No firewall IDs provided",
        )
    payload = firewall_ids
    logger.info("cancel_firmware_upgrade firewall_ids=%s", firewall_ids)
    response = central.delete(
        "/firewall/v1/firewalls/actions/firmware-upgrade",
        url_base=url_base,
        tenant_id=tenant_id,
        payload=payload,
    )
    if not response.success:
        logger.error(
            "cancel_firmware_upgrade failed: %s",
            getattr(response.value, "status_code", response.message),
        )
        return ReturnState(
            success=False,
            value=response.value,
            message=response.message or "cancel_firmware_upgrade request failed",
        )
    central_response = response.value
    status_codes = {
        201: "Upgrade cancelled successfully.",
        400: "Invalid request",
        401: "Authentication required",
        403: "Authorization required",
        404: "Firewall not found",
        500: "Unexpected error",
    }
    return ReturnState(
        success=central_response.success,
        message=status_codes.get(central_response.status_code, "Unexpected response"),
        value=central_response,
    )
