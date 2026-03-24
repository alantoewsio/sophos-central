import logging
from typing import List, Optional

from central.classes import ReturnState
from central.session import CentralSession
from central.firewalls.groups.classes import (
    FirewallID,
    FirewallSyncStatus,
    FirewallSyncStatuses,
    Group,
    Groups,
)

logger = logging.getLogger(__name__)


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewall-groups/get
def get_firewall_groups(
    central: CentralSession,
    recurseSubgroups: bool = True,
    search: str = None,
    searchFields: str = None,
    url_base: str = None,
    tenant_id: str = None,
) -> Groups:
    params = {}
    if recurseSubgroups is not None:
        params["recurseSubgroups"] = recurseSubgroups
    if search is not None:
        params["search"] = search
    if searchFields is not None:
        params["searchFields"] = searchFields
    logger.debug("get_firewall_groups params=%s tenant_id=%s", params, tenant_id)
    response = central.get(
        "/firewall/v1/firewall-groups",
        params=params,
        url_base=url_base,
        tenant_id=tenant_id,
    )
    groups = []
    if not response:
        logger.warning("get_firewall_groups returned no response")
        return response

    for group in response.value:
        if group:
            groups.append(Group(**group))
    logger.info("get_firewall_groups returned %d groups", len(groups))
    return Groups(groups)


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewall-groups/post
def create_firewall_group(
    central: CentralSession,
    name: str,
    assign_firewalls: List[str],
    config_import_source_firewall_id: Optional[str] = None,
    parent_group_id: Optional[str] = None,
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Create a firewall group."""
    payload = {
        "name": name,
        "assignFirewalls": assign_firewalls,
    }
    if config_import_source_firewall_id is not None:
        payload["configImportSourceFirewallId"] = config_import_source_firewall_id
    if parent_group_id is not None:
        payload["parentGroupId"] = parent_group_id
    logger.info("create_firewall_group name=%s", name)
    rs = central.post(
        "/firewall/v1/firewall-groups",
        payload=payload,
        url_base=url_base,
        tenant_id=tenant_id,
    )
    if rs.value is None:
        return ReturnState(success=False, message=rs.message or "Error: request failed")
    central_response = rs.value
    if not central_response.success:
        logger.error("create_firewall_group failed: %s", central_response.status_code)
    status_codes = {
        201: "Group created successfully",
        400: "Bad request",
        401: "Authentication required",
        403: "Authorization required",
        404: "Resource not found",
        500: "Unexpected error",
    }
    msg = status_codes.get(
        central_response.status_code,
        f"HTTP {central_response.status_code}",
    )
    out_value = Group(**central_response.data) if central_response.success else central_response
    return ReturnState(
        success=central_response.success,
        message=msg,
        value=out_value,
    )


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewall-groups/%7BgroupId%7D/patch
def update_firewall_group(
    central: CentralSession,
    group_id: str,
    name: Optional[str] = None,
    assign_firewalls: Optional[List[str]] = None,
    unassign_firewalls: Optional[List[str]] = None,
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Update a firewall group (name and/or firewall membership)."""
    payload = {}
    if name is not None:
        payload["name"] = name
    if assign_firewalls is not None:
        payload["assignFirewalls"] = assign_firewalls
    if unassign_firewalls is not None:
        payload["unassignFirewalls"] = unassign_firewalls
    if not payload:
        return ReturnState(
            success=False,
            message="Provide at least one of: name, assign_firewalls, unassign_firewalls",
        )
    logger.info("update_firewall_group group_id=%s", group_id)
    rs = central.patch(
        f"/firewall/v1/firewall-groups/{group_id}",
        payload=payload,
        url_base=url_base,
        tenant_id=tenant_id,
    )
    if rs.value is None:
        return ReturnState(success=False, message=rs.message or "Error: request failed")
    central_response = rs.value
    if not central_response.success:
        logger.error("update_firewall_group failed: %s", central_response.status_code)
    status_codes = {
        200: "Group updated successfully",
        400: "Bad request",
        401: "Authentication required",
        403: "Authorization required",
        404: "Resource not found",
        500: "Unexpected error",
    }
    msg = status_codes.get(
        central_response.status_code,
        f"HTTP {central_response.status_code}",
    )
    out_value = Group(**central_response.data) if central_response.success else central_response
    return ReturnState(
        success=central_response.success,
        message=msg,
        value=out_value,
    )


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewall-groups/%7BgroupId%7D/delete
def delete_firewall_group(
    central: CentralSession,
    group_id: str,
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Delete a firewall group by ID."""
    logger.info("delete_firewall_group group_id=%s", group_id)
    rs = central.delete(
        f"/firewall/v1/firewall-groups/{group_id}",
        url_base=url_base,
        tenant_id=tenant_id,
    )
    if rs.value is None:
        return ReturnState(success=False, message=rs.message or "Error: request failed")
    central_response = rs.value
    if not central_response.success:
        logger.error("delete_firewall_group failed: %s", central_response.status_code)
    status_codes = {
        200: "Group deleted successfully",
        401: "Authentication required",
        403: "Authorization required",
        404: "Resource not found",
        500: "Unexpected error",
    }
    msg = status_codes.get(
        central_response.status_code,
        f"HTTP {central_response.status_code}",
    )
    return ReturnState(
        success=central_response.success,
        message=msg,
        value=central_response,
    )


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewall-groups/%7BgroupId%7D/firewalls/sync-status/get
def get_firewall_group_sync_status(
    central: CentralSession,
    group_id: str,
    ids: Optional[List[str]] = None,
    url_base: str = None,
    tenant_id: str = None,
) -> FirewallSyncStatuses | ReturnState:
    """Synchronization status for firewalls in a group (paginated)."""
    params = {}
    if ids is not None:
        params["ids"] = ids
    logger.debug(
        "get_firewall_group_sync_status group_id=%s tenant_id=%s", group_id, tenant_id
    )
    response = central.get(
        f"/firewall/v1/firewall-groups/{group_id}/firewalls/sync-status",
        params=params or None,
        url_base=url_base,
        tenant_id=tenant_id,
    )
    if not response.success:
        logger.warning("get_firewall_group_sync_status failed")
        return response
    rows = []
    for row in response.value:
        if not row:
            continue
        rows.append(
            FirewallSyncStatus(
                firewall=FirewallID(**row["firewall"]),
                status=row["status"],
                lastUpdatedAt=row["lastUpdatedAt"],
            )
        )
    logger.info(
        "get_firewall_group_sync_status returned %d firewall status rows", len(rows)
    )
    return FirewallSyncStatuses(rows)
