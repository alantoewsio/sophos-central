"""Tests for central.firewalls.firmware.methods."""

from datetime import datetime
from unittest.mock import MagicMock

from central.classes import CentralResponse, ReturnState
from central.firewalls.firmware.classes import FirmwareUpgrade
from central.firewalls.firmware import methods as fm


def _ok_post_data(firewalls=None, versions=None):
    firewalls = firewalls or [{"id": "1", "serialNumber": "S", "firmwareVersion": "v", "upgradeToVersion": []}]
    versions = versions or []
    m = MagicMock(status_code=201)
    m.json.return_value = {"firewalls": firewalls, "firmwareVersions": versions}
    cr = CentralResponse(m)
    return ReturnState(success=True, value=cr)


def test_firmware_upgrade_check_empty():
    central = MagicMock()
    r = fm.firmware_upgrade_check(central, [])
    assert r.success is False


def test_firmware_upgrade_check_post_fail():
    central = MagicMock()
    cr = CentralResponse(MagicMock(status_code=500, json=lambda: {}))
    central.post.return_value = ReturnState(success=False, value=cr)
    r = fm.firmware_upgrade_check(central, ["a"])
    assert r.success is False


def test_firmware_upgrade_check_inner_fail():
    central = MagicMock()
    m = MagicMock(status_code=500, json=lambda: {})
    cr = CentralResponse(m)
    central.post.return_value = ReturnState(success=True, value=cr)
    r = fm.firmware_upgrade_check(central, ["a"])
    assert r.success is False


def test_firmware_upgrade_check_success():
    central = MagicMock()
    central.post.return_value = _ok_post_data(
        firewalls=[{"id": "1", "serialNumber": "S", "firmwareVersion": "v", "upgradeToVersion": ["x"]}],
        versions=[{"bugs": [], "news": [], "size": "1", "version": "v"}],
    )
    out = fm.firmware_upgrade_check(central, ["1"])
    assert out.success is True
    assert len(out.firewalls) == 1


def test_firmware_upgrade_check_skips_falsey_fw():
    central = MagicMock()
    central.post.return_value = _ok_post_data(
        firewalls=[None, {"id": "1", "serialNumber": "S", "firmwareVersion": "v", "upgradeToVersion": []}],
    )
    fm.firmware_upgrade_check(central, ["1"])


def test_firmware_upgrade_check_skips_falsey_firmware_version():
    """Cover branch 68->67: falsy entry in firmwareVersions list."""
    central = MagicMock()
    central.post.return_value = _ok_post_data(
        firewalls=[],
        versions=[None, {"bugs": [], "news": [], "size": "1", "version": "v"}],
    )
    out = fm.firmware_upgrade_check(central, ["1"])
    assert out.success is True
    assert len(out.firmwareVersions) == 1


def test_upgrade_firmware_empty_and_single_and_multi():
    central = MagicMock()
    m = MagicMock(status_code=201, json=lambda: {})
    cr = CentralResponse(m)
    central.post.return_value = ReturnState(success=True, value=cr)

    assert fm.upgrade_firmware(central, []).success is False
    u = FirmwareUpgrade(id="1", upgradeToVersion="19")
    r = fm.upgrade_firmware(central, u)
    assert r.success is True

    u2 = FirmwareUpgrade(id="2", upgradeToVersion="20", upgradeAt=datetime(2024, 6, 1))
    r2 = fm.upgrade_firmware(central, [u, u2])
    assert r2.success is True


def test_upgrade_firmware_post_fail():
    central = MagicMock()
    central.post.return_value = ReturnState(success=False, message="m", value=MagicMock())
    r = fm.upgrade_firmware(
        central, FirmwareUpgrade(id="1", upgradeToVersion="v")
    )
    assert r.success is False


def test_upgrade_firmware_unknown_status():
    central = MagicMock()
    m = MagicMock(status_code=418, json=lambda: {})
    cr = CentralResponse(m)
    central.post.return_value = ReturnState(success=True, value=cr)
    r = fm.upgrade_firmware(
        central, FirmwareUpgrade(id="1", upgradeToVersion="v")
    )
    assert "Unexpected" in r.message


def test_cancel_firmware_upgrade_empty_and_fail_and_ok():
    central = MagicMock()
    assert fm.cancel_firmware_upgrade(central, []).success is False
    central.delete.return_value = ReturnState(success=False, value=MagicMock(status_code=400))
    assert fm.cancel_firmware_upgrade(central, ["a"]).success is False

    m = MagicMock(status_code=201, json=lambda: {})
    cr = CentralResponse(m)
    central.delete.return_value = ReturnState(success=True, value=cr)
    r = fm.cancel_firmware_upgrade(central, ["a"])
    assert r.success is True


def test_cancel_unknown_status():
    central = MagicMock()
    m = MagicMock(status_code=222, json=lambda: {})
    cr = CentralResponse(m)
    central.delete.return_value = ReturnState(success=True, value=cr)
    r = fm.cancel_firmware_upgrade(central, ["a"])
    assert "Unexpected" in r.message
