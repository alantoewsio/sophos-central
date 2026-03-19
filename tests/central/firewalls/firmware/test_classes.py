"""Tests for central.firewalls.firmware.classes."""

from datetime import datetime

from central.firewalls.firmware.classes import (
    FirewallUpgrade,
    FirewallUpgradeInfo,
    FirmwareUpgrade,
    FirmwareVersion,
)


def test_firewall_upgrade_info_and_list_available():
    info = FirewallUpgradeInfo(
        firewalls=[
            {"id": "1", "serialNumber": "S", "firmwareVersion": "v", "upgradeToVersion": ["19"]},
            {"id": "2", "serialNumber": "S2", "firmwareVersion": "v", "upgradeToVersion": []},
        ],
        firmwareVersions=[{"bugs": [], "news": [], "size": "1", "version": "19"}],
    )
    assert info.success is True
    avail = info.list_available_upgrades()
    assert avail.count() == 1
    assert info.count_available_upgrades() == 1


def test_firmware_upgrade_dict_with_datetime():
    u = FirmwareUpgrade(id="1", upgradeToVersion="19.0", upgradeAt=datetime(2024, 1, 1))
    d = u.__dict__()
    assert "upgradeAt" in d


def test_firmware_version_dataclass():
    fv = FirmwareVersion(bugs=["b"], news=["n"], size="s", version="v")
    assert fv.version == "v"
