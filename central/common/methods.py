import logging
from typing import List, Optional

from central.classes import ReturnState
from central.session import CentralSession
from central.common.classes import Admin, Admins, Role, Roles

logger = logging.getLogger(__name__)


# https://developer.sophos.com/docs/common-v1/1/routes/roles/get
def get_roles(
    central: CentralSession,
    *,
    role_type: Optional[str] = None,
    principal_type: Optional[str] = None,
    fields: Optional[List[str]] = None,
    url_base: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Roles | ReturnState:
    """List tenant roles (Common API).

    Args:
        central: Authenticated session.
        role_type: API ``type`` query: ``predefined`` or ``custom``.
        principal_type: API ``principalType``: ``user`` or ``service``.
        fields: Optional partial-response field list.
        url_base: Data region base URL.
        tenant_id: Tenant UUID (``X-Tenant-ID``).

    Returns:
        :class:`Roles` on success, :class:`ReturnState` on failure.
    """
    params = {}
    if role_type is not None:
        params["type"] = role_type
    if principal_type is not None:
        params["principalType"] = principal_type
    if fields is not None:
        params["fields"] = fields

    logger.debug("get_roles params=%s tenant_id=%s", params, tenant_id)

    # Roles list has no documented page parameters; avoid sending pagination params.
    response = central.get(
        "/common/v1/roles",
        params=params if params else None,
        url_base=url_base,
        tenant_id=tenant_id,
        paginated=False,
    )

    if not response.success:
        logger.warning("get_roles failed")
        return ReturnState(
            success=False,
            value=response.value,
            message=getattr(
                response.value, "error_message", "error fetching roles"
            ),
        )

    items = response.value if response.value is not None else []
    roles = [Role(item) for item in items if item]
    logger.info("get_roles returned %d roles", len(roles))
    return Roles(roles)


# https://developer.sophos.com/docs/common-v1/1/routes/admins/get
def get_admins(
    central: CentralSession,
    *,
    sort: Optional[List[str]] = None,
    fields: Optional[List[str]] = None,
    search: Optional[str] = None,
    search_fields: Optional[List[str]] = None,
    role_id: Optional[str] = None,
    url_base: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Admins | ReturnState:
    """List tenant admins with page-based pagination (Common API).

    Args:
        central: Authenticated session.
        sort: Sort specs, e.g. ``["username:asc"]``.
        fields: Optional partial-response field list.
        search: Free-text search.
        search_fields: Fields to search (e.g. ``["username"]``).
        role_id: Filter by role UUID.
        url_base: Data region base URL.
        tenant_id: Tenant UUID (``X-Tenant-ID``).

    Returns:
        :class:`Admins` on success, :class:`ReturnState` on failure.
    """
    params = {}
    if sort is not None:
        params["sort"] = sort
    if fields is not None:
        params["fields"] = fields
    if search is not None:
        params["search"] = search
    if search_fields is not None:
        params["searchFields"] = search_fields
    if role_id is not None:
        params["roleId"] = role_id

    logger.debug("get_admins params=%s tenant_id=%s", params, tenant_id)

    response = central.get(
        "/common/v1/admins",
        params=params if params else None,
        url_base=url_base,
        tenant_id=tenant_id,
        paginated=True,
    )

    if not response.success:
        logger.warning("get_admins failed")
        return ReturnState(
            success=False,
            value=response.value,
            message=getattr(
                response.value, "error_message", "error fetching admins"
            ),
        )

    items = response.value if response.value is not None else []
    admins = [Admin(item) for item in items if item]
    logger.info("get_admins returned %d admins", len(admins))
    return Admins(admins)
