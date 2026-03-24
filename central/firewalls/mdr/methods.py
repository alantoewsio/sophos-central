"""MDR threat feed and async transaction helpers.

Paths are under ``/firewall/v1/firewall-config/firewalls/{firewallId}/...`` per the
`Firewall API <https://developer.sophos.com/docs/firewall-v1/1/overview>`_ OpenAPI spec
(server URL includes ``/firewall/v1``).
"""
from __future__ import annotations

import logging
from typing import List, Literal, Optional

from central.classes import ReturnState
from central.session import CentralSession

logger = logging.getLogger(__name__)

MdrThreatAction = Literal["logOnly", "logAndDrop"]


def _fc_root(firewall_id: str) -> str:
    return f"/firewall/v1/firewall-config/firewalls/{firewall_id}"


def _rs_to_return(rs: ReturnState, status_messages: dict[int, str]) -> ReturnState:
    if rs.value is None:
        return ReturnState(success=False, message=rs.message or "Error: request failed")
    cr = rs.value
    msg = status_messages.get(cr.status_code, f"HTTP {cr.status_code}")
    if not cr.success:
        logger.debug("mdr API status=%s", cr.status_code)
    return ReturnState(success=cr.success, message=msg, value=cr)


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewalls/%7BfirewallId%7D/mdr-threat-feed/get
def get_mdr_threat_feed(
    central: CentralSession,
    firewall_id: str,
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Start retrieval of MDR threat feed; poll :func:`get_firewall_transaction` with ``transactionId``."""
    rs = central.get_page(
        f"{_fc_root(firewall_id)}/mdr-threat-feed",
        paginated=False,
        url_base=url_base,
        tenant_id=tenant_id,
    )
    return _rs_to_return(
        rs,
        {
            202: "Request accepted",
            400: "Bad request",
            401: "Authentication required",
            403: "Authorization required",
            404: "Resource not found",
            500: "Unexpected error",
        },
    )


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewalls/%7BfirewallId%7D/mdr-threat-feed/settings/patch
def patch_mdr_threat_feed_settings(
    central: CentralSession,
    firewall_id: str,
    enabled: Optional[bool] = None,
    action: Optional[MdrThreatAction] = None,
    last_updated_at: Optional[str] = None,
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Update MDR threat-feed settings (async); poll transaction for completion."""
    payload = {}
    if enabled is not None:
        payload["enabled"] = enabled
    if action is not None:
        payload["action"] = action
    if last_updated_at is not None:
        payload["lastUpdatedAt"] = last_updated_at
    if not payload:
        return ReturnState(
            success=False,
            message="Provide at least one of: enabled, action, last_updated_at",
        )
    rs = central.patch(
        f"{_fc_root(firewall_id)}/mdr-threat-feed/settings",
        payload=payload,
        url_base=url_base,
        tenant_id=tenant_id,
    )
    return _rs_to_return(
        rs,
        {
            202: "Request accepted",
            400: "Bad request",
            401: "Authentication required",
            403: "Authorization required",
            404: "Resource not found",
            500: "Unexpected error",
        },
    )


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewalls/%7BfirewallId%7D/mdr-threat-feed/indicators/post
def create_mdr_threat_feed_indicators(
    central: CentralSession,
    firewall_id: str,
    indicators: List[dict],
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Create threat-feed indicators (async, max 100 per request)."""
    rs = central.post(
        f"{_fc_root(firewall_id)}/mdr-threat-feed/indicators",
        payload={"indicators": indicators},
        url_base=url_base,
        tenant_id=tenant_id,
    )
    return _rs_to_return(
        rs,
        {
            202: "Request accepted",
            400: "Bad request",
            401: "Authentication required",
            403: "Authorization required",
            404: "Resource not found",
            500: "Unexpected error",
        },
    )


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewalls/%7BfirewallId%7D/mdr-threat-feed/indicators/delete
def delete_all_mdr_threat_feed_indicators(
    central: CentralSession,
    firewall_id: str,
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Delete all MDR threat-feed indicators for the firewall (async)."""
    rs = central.delete(
        f"{_fc_root(firewall_id)}/mdr-threat-feed/indicators",
        url_base=url_base,
        tenant_id=tenant_id,
    )
    return _rs_to_return(
        rs,
        {
            202: "Request accepted",
            400: "Bad request",
            401: "Authentication required",
            403: "Authorization required",
            404: "Resource not found",
            500: "Unexpected error",
        },
    )


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewalls/%7BfirewallId%7D/mdr-threat-feed/indicators/delete/post
def delete_mdr_threat_feed_indicators(
    central: CentralSession,
    firewall_id: str,
    indicators: List[dict],
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Delete specific indicators (async); each item needs ``value`` and ``type`` (STIX)."""
    rs = central.post(
        f"{_fc_root(firewall_id)}/mdr-threat-feed/indicators/delete",
        payload={"indicators": indicators},
        url_base=url_base,
        tenant_id=tenant_id,
    )
    return _rs_to_return(
        rs,
        {
            202: "Request accepted",
            400: "Bad request",
            401: "Authentication required",
            403: "Authorization required",
            404: "Resource not found",
            500: "Unexpected error",
        },
    )


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewalls/%7BfirewallId%7D/mdr-threat-feed/indicators/search/post
def search_mdr_threat_feed_indicators(
    central: CentralSession,
    firewall_id: str,
    indicator_values: List[str],
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Search for indicators by value (async); poll transaction for results."""
    rs = central.post(
        f"{_fc_root(firewall_id)}/mdr-threat-feed/indicators/search",
        payload={"indicatorValues": indicator_values},
        url_base=url_base,
        tenant_id=tenant_id,
    )
    return _rs_to_return(
        rs,
        {
            202: "Request accepted",
            400: "Bad request",
            401: "Authentication required",
            403: "Authorization required",
            404: "Resource not found",
            500: "Unexpected error",
        },
    )


# https://developer.sophos.com/docs/firewall-v1/1/routes/firewalls/%7BfirewallId%7D/transactions/%7BtransactionId%7D/get
def get_firewall_transaction(
    central: CentralSession,
    firewall_id: str,
    transaction_id: str,
    fields: Optional[List[str]] = None,
    url_base: str = None,
    tenant_id: str = None,
) -> ReturnState:
    """Poll async MDR / firewall-config operations by transaction ID.

    Optional ``fields`` may include: request, response, expiryAt, finishedAt.
    """
    params = {}
    if fields:
        params["fields"] = ",".join(fields)
    rs = central.get_page(
        f"{_fc_root(firewall_id)}/transactions/{transaction_id}",
        params=params if params else None,
        paginated=False,
        url_base=url_base,
        tenant_id=tenant_id,
    )
    return _rs_to_return(
        rs,
        {
            200: "Transaction detail retrieved successfully",
            400: "Bad request",
            401: "Authentication required",
            403: "Authorization required",
            404: "Resource not found",
            500: "Unexpected error",
        },
    )
