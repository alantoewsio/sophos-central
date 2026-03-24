"""Tests for central.firewalls.groups.methods."""

from datetime import datetime
from unittest.mock import MagicMock

from central.classes import CentralResponse, ReturnState
from central.firewalls.groups.methods import (
    create_firewall_group,
    delete_firewall_group,
    get_firewall_group_sync_status,
    get_firewall_groups,
    update_firewall_group,
)


def _group_dict(gid="g1", parent=None):
    return {
        "id": gid,
        "name": "G",
        "parentGroup": parent,
        "tenant": {"id": "t"},
        "lockedByManagingAccount": False,
        "firewalls": {"total": 0, "itemsCount": 0, "items": []},
        "configImport": {
            "sourceFirewall": {"id": "s"},
            "percentComplete": 100,
            "status": "ok",
            "errors": [],
        },
        "createdBy": {"id": "", "type": "", "name": "", "accountId": "", "accountType": ""},
        "createdAt": datetime.now(),
        "updatedBy": {"id": "", "type": "", "name": "", "accountId": "", "accountType": ""},
        "updatedAt": datetime.now(),
    }


def test_get_firewall_groups_success():
    central = MagicMock()
    central.get.return_value = ReturnState(success=True, value=[_group_dict()])
    out = get_firewall_groups(central, recurseSubgroups=False, search="x", searchFields="name")
    assert len(out) == 1


def test_get_firewall_groups_failure():
    central = MagicMock()
    central.get.return_value = ReturnState(success=False)
    out = get_firewall_groups(central)
    assert out.success is False


def test_get_firewall_groups_recurse_none():
    central = MagicMock()
    central.get.return_value = ReturnState(success=True, value=[_group_dict()])
    out = get_firewall_groups(central, recurseSubgroups=None)
    assert len(out) == 1
    central.get.assert_called_once()
    assert central.get.call_args[1]["params"].get("recurseSubgroups") is None


def test_get_firewall_groups_skips_falsey_group():
    """Cover branch 37->36: falsy entry in response.value."""
    central = MagicMock()
    central.get.return_value = ReturnState(success=True, value=[None, _group_dict()])
    out = get_firewall_groups(central)
    assert len(out) == 1


def _mock_cr(code: int, data: dict | None = None):
    return CentralResponse(
        MagicMock(status_code=code, json=lambda: data if data is not None else {})
    )


def test_create_firewall_group_success():
    central = MagicMock()
    body = _group_dict()
    central.post.return_value = ReturnState(
        success=True, value=_mock_cr(201, body)
    )
    out = create_firewall_group(central, "My Group", assign_firewalls=["fw1"])
    assert out.success
    assert out.value.name == "G"


def test_create_firewall_group_no_value():
    central = MagicMock()
    central.post.return_value = ReturnState(
        success=False, message="Error: not authenticated", value=None
    )
    out = create_firewall_group(central, "My Group", assign_firewalls=["fw1"])
    assert out.success is False


def test_update_firewall_group_requires_field():
    out = update_firewall_group(MagicMock(), "gid")
    assert out.success is False


def test_delete_firewall_group_success():
    central = MagicMock()
    central.delete.return_value = ReturnState(
        success=True, value=_mock_cr(200, {"deleted": True})
    )
    out = delete_firewall_group(central, "gid")
    assert out.success


def test_get_firewall_group_sync_status_success():
    central = MagicMock()
    central.get.return_value = ReturnState(
        success=True,
        value=[
            {
                "firewall": {"id": "f1"},
                "status": "inSync",
                "lastUpdatedAt": "2022-05-18T11:20:26.657+00:00",
            }
        ],
    )
    out = get_firewall_group_sync_status(central, "gid", ids=["f1"])
    assert len(out) == 1
    assert list(out)[0].status == "inSync"


def test_get_firewall_group_sync_status_failure():
    central = MagicMock()
    central.get.return_value = ReturnState(success=False)
    out = get_firewall_group_sync_status(central, "gid")
    assert isinstance(out, ReturnState)
    assert out.success is False


def test_create_firewall_group_optional_payload_fields():
    central = MagicMock()
    body = _group_dict()
    central.post.return_value = ReturnState(
        success=True, value=_mock_cr(201, body)
    )
    create_firewall_group(
        central,
        "N",
        assign_firewalls=["a"],
        config_import_source_firewall_id="src",
        parent_group_id="par",
    )
    payload = central.post.call_args[1]["payload"]
    assert payload["configImportSourceFirewallId"] == "src"
    assert payload["parentGroupId"] == "par"


def test_create_firewall_group_http_error():
    central = MagicMock()
    central.post.return_value = ReturnState(success=True, value=_mock_cr(400, {}))
    out = create_firewall_group(central, "N", assign_firewalls=["a"])
    assert out.success is False
    assert out.value.status_code == 400


def test_create_firewall_group_unknown_status_message():
    central = MagicMock()
    central.post.return_value = ReturnState(success=True, value=_mock_cr(418, {}))
    out = create_firewall_group(central, "N", assign_firewalls=["a"])
    assert "418" in out.message


def test_update_firewall_group_success():
    central = MagicMock()
    body = _group_dict()
    central.patch.return_value = ReturnState(
        success=True, value=_mock_cr(200, body)
    )
    out = update_firewall_group(
        central, "gid", name="x", assign_firewalls=["a"], unassign_firewalls=["b"]
    )
    assert out.success
    pl = central.patch.call_args[1]["payload"]
    assert pl["assignFirewalls"] == ["a"] and pl["unassignFirewalls"] == ["b"]


def test_update_firewall_group_no_rs_value():
    central = MagicMock()
    central.patch.return_value = ReturnState(
        success=False, message="Error: not authenticated", value=None
    )
    out = update_firewall_group(central, "gid", name="n")
    assert out.success is False


def test_update_firewall_group_http_error():
    central = MagicMock()
    central.patch.return_value = ReturnState(success=True, value=_mock_cr(404, {}))
    out = update_firewall_group(central, "gid", name="n")
    assert out.success is False


def test_delete_firewall_group_no_rs_value():
    central = MagicMock()
    central.delete.return_value = ReturnState(
        success=False, value=None, message="x"
    )
    out = delete_firewall_group(central, "gid")
    assert out.success is False


def test_delete_firewall_group_http_error():
    central = MagicMock()
    central.delete.return_value = ReturnState(success=True, value=_mock_cr(500, {}))
    out = delete_firewall_group(central, "gid")
    assert out.success is False


def test_get_firewall_group_sync_status_skips_falsey_row():
    central = MagicMock()
    central.get.return_value = ReturnState(
        success=True,
        value=[
            None,
            {
                "firewall": {"id": "f1"},
                "status": "inSync",
                "lastUpdatedAt": "2022-05-18T11:20:26.657+00:00",
            },
        ],
    )
    out = get_firewall_group_sync_status(central, "gid")
    assert len(out) == 1
