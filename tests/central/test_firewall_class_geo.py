from datetime import datetime

from central.firewalls.firmware.classes import FirmwareUpgrade
from central.firewalls.classes import Firewall


def test_firmware_upgrade_dict_without_upgrade_at():
    """FirmwareUpgrade.__dict__() when upgradeAt is None (branch 60->63 not taken)."""
    u = FirmwareUpgrade(id="1", upgradeToVersion="19.0", upgradeAt=None)
    d = u.__dict__()
    assert "upgradeAt" not in d


def test_firewall_geolocation_populated():
    d = {
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
        "geoLocation": {"latitude": "1", "longitude": "2"},
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
    }
    fw = Firewall(d)
    assert fw.geoLocation is not None
