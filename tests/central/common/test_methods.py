"""Tests for central.common.methods."""

from unittest.mock import MagicMock

from central.classes import CentralResponse, ReturnState
from central.common.methods import get_admins, get_roles


def test_get_roles_success():
    central = MagicMock()
    central.get.return_value = ReturnState(
        success=True,
        value=[
            {
                "id": "r1",
                "name": "Admin",
                "type": "predefined",
                "principalType": "user",
                "permissionSets": ["a"],
            }
        ],
    )
    out = get_roles(central, tenant_id="t")
    roles = list(out)
    assert len(roles) == 1
    assert roles[0].id == "r1"
    assert roles[0].permissionSets == ["a"]


def test_get_roles_failure():
    central = MagicMock()
    cr = CentralResponse(MagicMock(status_code=403, json=lambda: {"error": "e"}))
    cr.error_message = "e"
    central.get.return_value = ReturnState(success=False, value=cr)
    out = get_roles(central)
    assert out.success is False


def test_get_admins_success():
    central = MagicMock()
    central.get.return_value = ReturnState(
        success=True,
        value=[
            {
                "id": "a1",
                "tenant": {"id": "t1"},
                "users": [],
                "profile": {"name": "N", "email": "e@x"},
                "roleAssignments": [],
            }
        ],
    )
    out = get_admins(central, tenant_id="t")
    admins = list(out)
    assert len(admins) == 1
    assert admins[0].id == "a1"


def test_get_admins_failure():
    central = MagicMock()
    cr = CentralResponse(MagicMock(status_code=500, json=lambda: {}))
    central.get.return_value = ReturnState(success=False, value=cr)
    out = get_admins(central)
    assert out.success is False


def test_get_roles_passes_query_params():
    central = MagicMock()
    central.get.return_value = ReturnState(success=True, value=[])
    get_roles(
        central,
        role_type="predefined",
        principal_type="user",
        fields=["id", "name"],
        tenant_id="t1",
        url_base="https://eu.central.sophos.com/",
    )
    args, kwargs = central.get.call_args
    assert args[0] == "/common/v1/roles"
    assert kwargs["params"]["type"] == "predefined"
    assert kwargs["params"]["principalType"] == "user"
    assert kwargs["params"]["fields"] == ["id", "name"]
    assert kwargs["paginated"] is False


def test_get_admins_passes_query_params_and_pagination():
    central = MagicMock()
    central.get.return_value = ReturnState(success=True, value=[])
    get_admins(
        central,
        sort=["username:asc"],
        search="bob",
        search_fields=["username"],
        role_id="rid",
        fields=["id"],
        tenant_id="t1",
    )
    kwargs = central.get.call_args.kwargs
    p = kwargs["params"]
    assert p["sort"] == ["username:asc"]
    assert p["search"] == "bob"
    assert p["searchFields"] == ["username"]
    assert p["roleId"] == "rid"
    assert p["fields"] == ["id"]
    assert kwargs["paginated"] is True
