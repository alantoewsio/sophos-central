import logging
from typing import List

from central.classes import ReturnState
from central.session import CentralSession
from central.alerts.classes import Alert, AlertActionResult, Alerts

logger = logging.getLogger(__name__)


# https://developer.sophos.com/docs/common-v1/1/routes/alerts/get
def get_alerts(
    central: CentralSession,
    group_key: str = None,
    from_time: str = None,
    to_time: str = None,
    sort: List[str] = None,
    product: List[str] = None,
    category: List[str] = None,
    severity: List[str] = None,
    ids: List[str] = None,
    fields: List[str] = None,
    page_size: int = 100,
    page_total: bool = True,
    url_base: str = None,
    tenant_id: str = None,
) -> Alerts | ReturnState:
    """Get alerts matching criteria in query parameters.

    Args:
        central: CentralSession object
        group_key: Optional filter by alert group key
        from_time: Alerts raised on or after this time (ISO 8601 datetime)
        to_time: Alerts raised before this time (ISO 8601 datetime)
        sort: Sort spec, e.g. ["raisedAt:desc"]
        product: Filter by product types (endpoint, server, firewall, etc.)
        category: Filter by alert categories
        severity: Filter by severity (high, medium, low)
        ids: List of alert IDs to fetch
        fields: Fields to return in partial response
        page_size: Page size (default 100, max 1000)
        page_total: Whether to request total count
        url_base: Optional base URL
        tenant_id: Optional tenant ID (X-Tenant-ID)

    Returns:
        Alerts container on success, ReturnState on failure
    """
    params = {"pageSize": min(page_size, 1000), "pageTotal": page_total}
    if group_key is not None:
        params["groupKey"] = group_key
    if from_time is not None:
        params["from"] = from_time
    if to_time is not None:
        params["to"] = to_time
    if sort is not None:
        params["sort"] = sort
    if product is not None:
        params["product"] = product
    if category is not None:
        params["category"] = category
    if severity is not None:
        params["severity"] = severity
    if ids is not None:
        params["ids"] = ids
    if fields is not None:
        params["fields"] = fields

    logger.debug("get_alerts params=%s tenant_id=%s", params, tenant_id)

    response = central.get(
        "/common/v1/alerts",
        params=params,
        url_base=url_base,
        tenant_id=tenant_id,
        paginated=False,
    )

    if not response.success:
        logger.warning("get_alerts returned no response or error")
        return ReturnState(
            success=False,
            value=response.value,
            message=getattr(
                response.value, "error_message", "error fetching alerts"
            ),
        )

    items = response.value if response.value is not None else []
    alerts = [Alert(item) for item in items if item]
    logger.info("get_alerts returned %d alerts", len(alerts))
    return Alerts(alerts)


# https://developer.sophos.com/docs/common-v1/1/routes/alerts/%7BalertId%7D/get
def get_alert(
    central: CentralSession,
    alert_id: str,
    fields: List[str] = None,
    url_base: str = None,
    tenant_id: str = None,
) -> Alert | ReturnState:
    """Get a single alert by ID.

    Args:
        central: CentralSession object
        alert_id: UUID of the alert
        fields: Optional list of fields to return (partial response)
        url_base: Optional base URL
        tenant_id: Optional tenant ID (X-Tenant-ID, required for tenant-scoped API)

    Returns:
        Alert on success, ReturnState on failure
    """
    params = {}
    if fields is not None:
        params["fields"] = fields

    logger.debug("get_alert alert_id=%s tenant_id=%s", alert_id, tenant_id)

    response = central.get_page(
        f"/common/v1/alerts/{alert_id}",
        params=params if params else None,
        url_base=url_base,
        tenant_id=tenant_id,
        paginated=False,
    )

    if not response.success:
        logger.warning("get_alert failed for alert_id=%s", alert_id)
        return ReturnState(
            success=False,
            value=response.value,
            message=getattr(
                response.value, "error_message", "error fetching alert"
            ),
        )

    # Single-alert response body is the alert object itself (not wrapped in items)
    data = getattr(response.value, "data", None)
    if not data:
        return ReturnState(
            success=False,
            value=response.value,
            message="alert response contained no data",
        )

    return Alert(data)


# https://developer.sophos.com/docs/common-v1/1/routes/alerts/search/post
def search_alerts(
    central: CentralSession,
    group_key: str = None,
    from_time: str = None,
    to_time: str = None,
    sort: List[str] = None,
    product: List[str] = None,
    category: List[str] = None,
    severity: List[str] = None,
    ids: List[str] = None,
    fields: List[str] = None,
    page_size: int = 100,
    page_total: bool = True,
    url_base: str = None,
    tenant_id: str = None,
) -> Alerts | ReturnState:
    """Query alerts via POST with a JSON body (same filters as GET list, plus pagination in body).

    See also ``get_alerts`` for the GET variant. This endpoint follows the same response shape
    (``items`` + key-based ``pages.nextKey``) and is paginated automatically when ``nextKey`` is present.

    Args:
        central: CentralSession object
        group_key: Optional filter by alert group key
        from_time: Alerts raised on or after this time (ISO 8601 datetime)
        to_time: Alerts raised before this time (ISO 8601 datetime)
        sort: Sort spec, e.g. ["raisedAt:desc"]
        product: Filter by product types
        category: Filter by alert categories
        severity: Filter by severity (high, medium, low)
        ids: List of alert IDs
        fields: Fields to return in partial response
        page_size: Page size (max 1000)
        page_total: Whether to request total count in pages metadata
        url_base: Optional base URL
        tenant_id: Optional tenant ID (X-Tenant-ID)

    Returns:
        Alerts container on success, ReturnState on failure
    """
    payload = {"pageSize": min(page_size, 1000), "pageTotal": page_total}
    if group_key is not None:
        payload["groupKey"] = group_key
    if from_time is not None:
        payload["from"] = from_time
    if to_time is not None:
        payload["to"] = to_time
    if sort is not None:
        payload["sort"] = sort
    if product is not None:
        payload["product"] = product
    if category is not None:
        payload["category"] = category
    if severity is not None:
        payload["severity"] = severity
    if ids is not None:
        payload["ids"] = ids
    if fields is not None:
        payload["fields"] = fields

    logger.debug("search_alerts payload keys=%s tenant_id=%s", list(payload.keys()), tenant_id)

    items: List[dict] = []
    next_key = None
    first = True

    while first or next_key:
        body = dict(payload)
        if next_key is not None:
            body["pageFromKey"] = next_key

        response = central.post(
            "/common/v1/alerts/search",
            payload=body,
            url_base=url_base,
            tenant_id=tenant_id,
        )
        first = False

        if not response.success:
            logger.warning("search_alerts request failed")
            return ReturnState(
                success=False,
                value=response.value,
                message=getattr(
                    response.value, "error_message", "error searching alerts"
                ),
            )

        cr = response.value
        if cr.items is not None:
            items.extend(item for item in cr.items if item)
        next_key = (
            getattr(cr.pages, "nextKey", None) if getattr(cr, "pages", None) else None
        )
        if not next_key:
            break

    alerts = [Alert(item) for item in items]
    logger.info("search_alerts returned %d alerts", len(alerts))
    return Alerts(alerts)


# https://developer.sophos.com/docs/common-v1/1/routes/alerts/%7BalertId%7D/actions/post
def take_alert_action(
    central: CentralSession,
    alert_id: str,
    action: str,
    message: str = None,
    url_base: str = None,
    tenant_id: str = None,
) -> AlertActionResult | ReturnState:
    """Perform an allowed action on an alert (acknowledge, cleanPua, etc.).

    Args:
        central: CentralSession object
        alert_id: UUID of the alert
        action: One of acknowledge, cleanPua, cleanVirus, authPua, clearThreat,
            clearHmpa, sendMsgPua, sendMsgThreat
        message: Optional message (e.g. for sendMsg* actions)
        url_base: Optional base URL
        tenant_id: Optional tenant ID (X-Tenant-ID)

    Returns:
        AlertActionResult on success (HTTP 201), ReturnState on failure
    """
    body: dict = {"action": action}
    if message is not None:
        body["message"] = message

    logger.debug(
        "take_alert_action alert_id=%s action=%s tenant_id=%s",
        alert_id,
        action,
        tenant_id,
    )

    response = central.post(
        f"/common/v1/alerts/{alert_id}/actions",
        payload=body,
        url_base=url_base,
        tenant_id=tenant_id,
    )

    if not response.success:
        logger.warning("take_alert_action failed for alert_id=%s", alert_id)
        return ReturnState(
            success=False,
            value=response.value,
            message=getattr(
                response.value, "error_message", "error performing alert action"
            ),
        )

    cr = response.value
    data = getattr(cr, "data", None)
    if not data or not isinstance(data, dict):
        return ReturnState(
            success=False,
            value=cr,
            message="alert action response contained no data",
        )

    return AlertActionResult(data)
