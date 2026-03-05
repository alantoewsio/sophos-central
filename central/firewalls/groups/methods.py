import logging
from typing import List
from central.session import CentralSession
from central.firewalls.groups.classes import Group, Groups

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
