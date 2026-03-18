import logging

from central.classes import ReturnState
from central.session import CentralSession
from central.firewalls.licenses.classes import License, Licenses

logger = logging.getLogger(__name__)


# https://developer.sophos.com/docs/licensing-v1/1/routes/licenses/firewalls/get
def get_licenses(
    central: CentralSession,
    tenant_id: str = None,
    partner_id: str = None,
    sort: str = None,
    url_base: str = None,
) -> Licenses | ReturnState:
    params = {}
    if sort is not None:
        params["sort"] = sort
    logger.debug(
        "get_licenses tenant_id=%s partner_id=%s sort=%s url_base=%s",
        tenant_id,
        partner_id,
        sort,
        url_base,
    )
    response = central.get(
        "/licenses/v1/licenses/firewalls",
        params=params,
        url_base=url_base,
        tenant_id=tenant_id,
        partner_id=partner_id,
        paginated=False,
    )
    if not response.success:
        logger.error("get_licenses failed: %s", getattr(response, "message", response))
        return ReturnState(
            success=False,
            value=response,
            message=f"error: received status code {response.value.status_code}",
        )
    licenses = []
    for license in response.value:
        if license:
            licenses.append(License(**license))
    logger.info("get_licenses returned %d license records", len(licenses))
    return Licenses(licenses)
