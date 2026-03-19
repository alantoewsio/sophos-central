"""Cover error logging branches in central.firewalls.methods."""

from unittest.mock import MagicMock, patch

from central.classes import CentralResponse, ReturnState
from central.firewalls.methods import (
    approve_management,
    cancel_firmware_upgrade,
    delete_firewall,
    firmware_upgrade_check,
    schedule_firmware_upgrade,
    set_firewall_location_and_label,
)


def _unwrap(x):
    if isinstance(x, ReturnState) and x.value is not None:
        return x.value
    return CentralResponse(x) if hasattr(x, "status_code") else x


@patch("central.firewalls.methods.CentralResponse", side_effect=_unwrap)
def test_set_firewall_location_error_logs(mock_cr):
    central = MagicMock()
    central.patch.return_value = ReturnState(
        success=True,
        value=CentralResponse(MagicMock(status_code=500, json=lambda: {})),
    )
    set_firewall_location_and_label(central, "f", label="abc")


@patch("central.firewalls.methods.CentralResponse", side_effect=_unwrap)
def test_delete_firewall_error_log(mock_cr):
    central = MagicMock()
    central.delete.return_value = ReturnState(
        success=True,
        value=CentralResponse(MagicMock(status_code=404, json=lambda: {})),
    )
    delete_firewall(central, "f")


@patch("central.firewalls.methods.CentralResponse", side_effect=_unwrap)
def test_approve_management_error_log(mock_cr):
    central = MagicMock()
    central.post.return_value = ReturnState(
        success=True,
        value=CentralResponse(MagicMock(status_code=403, json=lambda: {})),
    )
    approve_management(central, "f")


@patch("central.firewalls.methods.CentralResponse", side_effect=_unwrap)
def test_firmware_upgrade_check_methods_error(mock_cr):
    central = MagicMock()
    central.post.return_value = ReturnState(
        success=True,
        value=CentralResponse(MagicMock(status_code=500, json=lambda: {})),
    )
    firmware_upgrade_check(central, ["a"])


@patch("central.firewalls.methods.CentralResponse", side_effect=_unwrap)
def test_schedule_firmware_error(mock_cr):
    central = MagicMock()
    central.post.return_value = ReturnState(
        success=True,
        value=CentralResponse(MagicMock(status_code=400, json=lambda: {})),
    )
    schedule_firmware_upgrade(central, "f", "v")


@patch("central.firewalls.methods.CentralResponse", side_effect=_unwrap)
def test_cancel_firmware_methods_error(mock_cr):
    central = MagicMock()
    central.delete.return_value = ReturnState(
        success=True,
        value=CentralResponse(MagicMock(status_code=500, json=lambda: {})),
    )
    cancel_firmware_upgrade(central, ["a"], "v")
