import logging
from typing import List, Optional
from central.classes import CentralResponse, ReturnState
from central.session import CentralSession
from central.firewalls.classes import Firewall, Firewalls

logger = logging.getLogger(__name__)


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewalls/get
def get_firewalls(
    central: CentralSession,
    group_id: str = None,
    search: str = None,
    url_base: str = None,
    tenant_id: str = None,
) -> Firewalls | ReturnState:
    """Get a list of firewalls.
    Args:
        central: CentralSession object
        group_id: str, optional, the ID of the group to filter by
        search: str, optional, the search string to filter by
        url_base: str, optional, the base URL of the API
        tenant_id: str, optional, the ID of the tenant containing the target firewalls
    Returns:
        List[Firewall], a list of Firewall objects
    """
    params = {}
    if group_id is not None:
        params["groupID"] = group_id
    if search is not None:
        params["search"] = search
    logger.debug(
        "get_firewalls params=%s tenant_id=%s partner_id=%s",
        params,
        tenant_id,
    )
    response = central.get(
        "/firewall/v1/firewalls",
        params=params,
        url_base=url_base,
        tenant_id=tenant_id,
    )
    firewalls = []
    if not response:
        logger.warning("get_firewalls returned no response")
        return ReturnState(
            success=False,
            value=response,
            message=f"error: received status code {response.value.status_code}",
        )

    for firewall in response.value:
        if firewall:
            firewalls.append(Firewall(firewall))
    logger.info("get_firewalls returned %d firewalls", len(firewalls))

    # status_codes = {
    #     200: "List of firewalls",
    #     401: "Authentication required",
    #     403: "Authorization required",
    #     404: "Firewall not found",
    #     500: "Unexpected error",
    # }
    # return ReturnState(
    #     success=response.status_code in status_codes, return_value=response
    # )
    return Firewalls(firewalls)


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewalls/%7BfirewallId%7D/patch
def set_firewall_location_and_label(
    central: CentralSession,
    firewall_id: str,
    latitude: Optional[float] = None,
    longitude: Optional[float] = None,
    label: Optional[str] = None,
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Set the location and label of a firewall.
    Args:
        central: CentralSession object
        firewall_id: str, the ID of the firewall to set the location and label of
        latitude: float, optional, the latitude of the firewall
        longitude: float, optional, the longitude of the firewall
        label: str, optional, the label of the firewall
        url_base: str, optional, the base URL of the API
        tenant_id: str, optional, the ID of the tenant containing the target firewall
    Returns:
        ReturnState, a ReturnState object with return_value containing the CentralResponse object
    """
    payload = {}
    if 3 <= len(label) <= 40:
        payload["name"] = label
    else:
        payload["name"] = None
    if latitude is not None and longitude is not None:
        payload["geoLocation"] = {
            "latitude": str(round(latitude, 2)),
            "longitude": str(round(longitude, 2)),
        }
    else:
        payload["geoLocation"] = None

    logger.debug("set_firewall_location_and_label firewall_id=%s", firewall_id)
    response = central.patch(
        f"/firewall/v1/firewalls/{firewall_id}",
        payload=payload,
        url_base=url_base,
        tenant_id=tenant_id,
    )
    central_response = CentralResponse(response)
    if not central_response.success:
        logger.error(
            "set_firewall_location_and_label failed: %s", central_response.status_code
        )

    status_codes = {
        200: "Firewall updated successfully",
        400: "Invalid firewall ID",
        401: "Authentication required",
        403: "Authorization required",
        404: "Firewall not found",
        409: "Firewall name already in use",
        500: "Unexpected error",
    }
    return ReturnState(
        success=central_response.success,
        message=status_codes[central_response.status_code],
        value=central_response,
    )


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewalls/%7BfirewallId%7D/delete
def delete_firewall(
    central: CentralSession,
    firewall_id: str,
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Delete a firewall.
    Args:
        central: CentralSession object
        firewall_id: str, the ID of the firewall to delete
        url_base: str, optional, the base URL of the API
        tenant_id: str, optional, the ID of the tenant containing the target firewall
    Returns:
        ReturnState, a ReturnState object with return_value containing the CentralResponse object
    """
    logger.info("delete_firewall firewall_id=%s", firewall_id)
    response = central.delete(
        f"/firewall/v1/firewalls/{firewall_id}",
        url_base=url_base,
        tenant_id=tenant_id,
    )
    central_response = CentralResponse(response)
    if not central_response.success:
        logger.error("delete_firewall failed: %s", central_response.status_code)
    status_codes = {
        200: "Firewall deleted successfully",
        401: "Authentication required",
        403: "Authorization required",
        404: "Firewall not found",
        500: "Unexpected error",
    }
    return ReturnState(
        success=central_response.success,
        message=status_codes[central_response.status_code],
        value=central_response,
    )


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewalls/%7BfirewallId%7D/action/post
def approve_management(
    central: CentralSession,
    firewall_id: str,
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Approve management of a firewall.
    Args:
        central: CentralSession object
        firewall_id: str, the ID of the firewall to approve management of
        url_base: str, optional, the base URL of the API
        tenant_id: str, optional, the ID of the tenant containing the target firewall
    Returns:
        ReturnState, a ReturnState object with return_value containing the CentralResponse object
    """
    logger.info("approve_management firewall_id=%s", firewall_id)
    payload = {
        "action": "approveManagement",
    }
    response = central.post(
        f"/firewall/v1/firewalls/{firewall_id}/action",
        payload=payload,
        url_base=url_base,
        tenant_id=tenant_id,
    )
    central_response = CentralResponse(response)
    if not central_response.success:
        logger.error("approve_management failed: %s", central_response.status_code)
    status_codes = {
        201: "Firewall action completed successfully.",
        400: "Invalid request",
        401: "Authentication required",
        403: "Authorization required",
        404: "Firewall not found",
        500: "Unexpected error",
    }
    return ReturnState(
        success=central_response.success,
        message=status_codes[central_response.status_code],
        value=central_response,
    )


def firmware_upgrade_check(
    central: CentralSession,
    firewall_ids: List[str],
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Check if a firmware upgrade is available for a firewall.
    Args:
        central: CentralSession object
        firewall_ids: List[str], the IDs of the firewalls to check if a firmware upgrade is available for
        url_base: str, optional, the base URL of the API
        tenant_id: str, optional, the ID of the tenant containing the target firewalls
    Returns:
        ReturnState, a ReturnState object with return_value containing the CentralResponse object
    """
    logger.debug("firmware_upgrade_check firewall_ids=%s", firewall_ids)
    payload = {
        "firewalls": firewall_ids,
    }
    response = central.post(
        "/firewall/v1/firewalls/actions/firmware-upgrade-check",
        payload=payload,
        url_base=url_base,
        tenant_id=tenant_id,
    )
    central_response = CentralResponse(response)
    if not central_response.success:
        logger.error("firmware_upgrade_check failed: %s", central_response.status_code)
    status_codes = {
        201: "List of available upgrades.",
        400: "Invalid request",
        401: "Authentication required",
        403: "Authorization required",
        404: "Firewall not found",
        500: "Unexpected error",
    }
    return ReturnState(
        success=central_response.success,
        message=status_codes[central_response.status_code],
        value=central_response,
    )


def schedule_firmware_upgrade(
    central: CentralSession,
    firewall_id: str,
    upgradeToVersion: str,
    upgrade_at: Optional[str] = None,
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Upgrade the firmware of a firewall.
    Args:
        central: CentralSession object
        firewall_id: str, Firewall ID
        upgradeToVersion: str, Version of the firewall to you want to upgrade to.
        upgrade_at: Optional[str] = None, Schedule time in "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'". If not present, considered to be schedule now.
        url_base: str, optional, the base URL of the API
        tenant_id: str, optional, the ID of the tenant containing the target firewalls
    """
    logger.info(
        "schedule_firmware_upgrade firewall_id=%s version=%s",
        firewall_id,
        upgradeToVersion,
    )
    payload = {
        "id": firewall_id,
        "upgradeToVersion": upgradeToVersion,
        "upgradeAt": upgrade_at,
    }
    response = central.post(
        "/firewall/v1/firewalls/actions/firmware-upgrade",
        payload=payload,
        url_base=url_base,
        tenant_id=tenant_id,
    )
    central_response = CentralResponse(response)
    if not central_response.success:
        logger.error(
            "schedule_firmware_upgrade failed: %s", central_response.status_code
        )
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
        message=status_codes[central_response.status_code],
        value=central_response,
    )


def cancel_firmware_upgrade(
    central: CentralSession,
    firewall_ids: List[str],
    upgradeToVersion: str,
    upgrade_at: Optional[str] = None,
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Upgrade the firmware of a firewall.
    Args:
        central: CentralSession object
        firewall_id: str, Firewall ID
        upgradeToVersion: str, Version of the firewall to you want to upgrade to.
        upgrade_at: Optional[str] = None, Schedule time in "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'". If not present, considered to be schedule now.
        url_base: str, optional, the base URL of the API
        tenant_id: str, optional, the ID of the tenant containing the target firewalls
    """
    logger.info("cancel_firmware_upgrade firewall_ids=%s", firewall_ids)
    payload = firewall_ids

    response = central.delete(
        "/firewall/v1/firewalls/actions/firmware-upgrade",
        payload=payload,
        url_base=url_base,
        tenant_id=tenant_id,
    )
    central_response = CentralResponse(response)
    if not central_response.success:
        logger.error("cancel_firmware_upgrade failed: %s", central_response.status_code)
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
        message=status_codes[central_response.status_code],
        value=central_response,
    )
