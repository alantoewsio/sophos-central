"""Tests for central.firewalls.methods."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from central.classes import CentralResponse, ReturnState
from central.firewalls.methods import (
    approve_management,
    cancel_firmware_upgrade,
    delete_firewall,
    firmware_upgrade_check,
    get_firewalls,
    schedule_firmware_upgrade,
    set_firewall_location_and_label,
)


def _rs_from_status(code: int):
    r = MagicMock(status_code=code, json=lambda: {})
    cr = CentralResponse(r)
    return ReturnState(success=cr.success, value=cr)


def _patch_central_response_in_firewall_methods():
    """methods pass ReturnState into CentralResponse; unwrap to inner response."""

    def _unwrap(x):
        if isinstance(x, ReturnState) and x.value is not None:
            return x.value
        return CentralResponse(x) if hasattr(x, "status_code") else x

    return patch("central.firewalls.methods.CentralResponse", side_effect=_unwrap)


def test_get_firewalls_success():
    central = MagicMock()
    central.get.return_value = ReturnState(
        success=True, value=[{"id": "1", "cluster": None, "tenant": {"id": "t"}, "serialNumber": "S", "group": None, "hostname": "h", "name": "n", "externalIpv4Addresses": [], "firmwareVersion": "v", "model": "m", "status": {"managingStatus": "approved", "reportingStatus": "approved", "connected": False, "suspended": False}, "stateChangedAt": "", "capabilities": [], "geoLocation": None, "createdBy": {"id": "", "type": "", "name": "", "accountType": "", "accountId": ""}, "createdAt": "", "updatedAt": "", "updatedBy": {"id": "", "type": "", "name": "", "accountType": "", "accountId": ""}}]
    )
    out = get_firewalls(central, group_id="g", search="x", tenant_id="t")
    assert len(out) == 1


def test_get_firewalls_failure():
    central = MagicMock()
    r = MagicMock(status_code=403, json=lambda: {})
    cr = CentralResponse(r)
    central.get.return_value = ReturnState(success=False, value=cr)
    out = get_firewalls(central)
    assert isinstance(out, ReturnState)
    assert out.success is False


def test_get_firewalls_skips_empty_entries():
    central = MagicMock()
    central.get.return_value = ReturnState(
        success=True,
        value=[
            None,
            {
                "id": "1",
                "cluster": None,
                "tenant": {"id": "t"},
                "serialNumber": "S",
                "group": None,
                "hostname": "h",
                "name": "n",
                "externalIpv4Addresses": [],
                "firmwareVersion": "v",
                "model": "m",
                "status": {
                    "managingStatus": "a",
                    "reportingStatus": "a",
                    "connected": False,
                    "suspended": False,
                },
                "stateChangedAt": "",
                "capabilities": [],
                "geoLocation": None,
                "createdBy": {
                    "id": "",
                    "type": "",
                    "name": "",
                    "accountType": "",
                    "accountId": "",
                },
                "createdAt": "",
                "updatedAt": "",
                "updatedBy": {
                    "id": "",
                    "type": "",
                    "name": "",
                    "accountType": "",
                    "accountId": "",
                },
            },
        ],
    )
    out = get_firewalls(central)
    assert len(out) == 1


@pytest.mark.parametrize(
    "fn,kwargs",
    [
        (set_firewall_location_and_label, {"firewall_id": "f", "label": "goodlabel", "latitude": 1.0, "longitude": 2.0}),
        (set_firewall_location_and_label, {"firewall_id": "f", "label": "ab"}),
        (delete_firewall, {"firewall_id": "f"}),
        (approve_management, {"firewall_id": "f"}),
        (firmware_upgrade_check, {"firewall_ids": ["a"]}),
        (schedule_firmware_upgrade, {"firewall_id": "f", "upgradeToVersion": "v"}),
        (cancel_firmware_upgrade, {"firewall_ids": ["a"], "upgradeToVersion": "v"}),
    ],
)
def test_firewall_actions_success(fn, kwargs):
    central = MagicMock()
    central.patch.return_value = _rs_from_status(200)
    central.delete.return_value = _rs_from_status(
        201 if fn is cancel_firmware_upgrade else 200
    )
    central.post.return_value = _rs_from_status(201)
    with _patch_central_response_in_firewall_methods():
        r = fn(central, **kwargs)
    assert r.success is True


def test_firewall_actions_error_paths():
    central = MagicMock()
    central.patch.return_value = _rs_from_status(500)
    with _patch_central_response_in_firewall_methods():
        r = set_firewall_location_and_label(central, "f", label="good")
    assert r.success is False
