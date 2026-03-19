"""Tests for central.firewalls.groups.methods."""

from datetime import datetime
from unittest.mock import MagicMock

from central.classes import ReturnState
from central.firewalls.groups.methods import get_firewall_groups


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
