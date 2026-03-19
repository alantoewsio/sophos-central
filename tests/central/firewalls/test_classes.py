"""Tests for central.firewalls.classes."""

from central.firewalls.classes import Firewall, Firewalls


def _fw_dict(fid="1", group=None, cluster=None):
    return {
        "id": fid,
        "cluster": cluster,
        "tenant": {"id": "t"},
        "serialNumber": "SN",
        "group": group,
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
    }


def test_firewall_cluster_and_group_variants():
    fw = Firewall(_fw_dict(cluster=None, group=None))
    assert fw.cluster is None
    assert fw.group is None
    fw2 = Firewall(
        _fw_dict(
            cluster={"id": "c", "mode": "m", "status": "s", "peers": {"id": "p", "serialNumber": "s"}},
            group={"id": "g", "name": "G"},
        )
    )
    assert fw2.cluster is not None
    assert fw2.group is not None


def test_firewalls_helpers():
    fws = Firewalls(
        [
            Firewall(_fw_dict("1", group={"id": "g1", "name": "A"})),
            Firewall(_fw_dict("2", group={"id": "g2", "name": "B"})),
        ]
    )
    assert fws.get_firewall_by_id("1") is not None
    assert fws.get_firewall_by_name("n") is not None
    assert fws.find_firewalls_by_name("n") is not None
    assert fws.get_firewalls_by_group_id("g1") is None  # attr "group.id" not resolved on object
    assert fws.get_firewalls_by_group_name("A") is None
