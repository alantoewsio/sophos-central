"""Tests for central.firewalls.groups.classes."""

from datetime import datetime

from central.firewalls.groups.classes import Group, Groups


def _g(pid=None):
    return Group(
        id="1",
        name="Root",
        parentGroup=type("P", (), {"id": pid})() if pid else None,
        tenant=type("T", (), {"id": "t"})(),
        lockedByManagingAccount=False,
        firewalls=type("F", (), {"total": 0, "itemsCount": 0, "items": []})(),
        configImport=type(
            "C",
            (),
            {
                "sourceFirewall": type("S", (), {"id": "s"})(),
                "percentComplete": 0,
                "status": "",
                "errors": [],
            },
        )(),
        createdBy=type("U", (), {"id": "", "type": "", "name": "", "accountId": "", "accountType": ""})(),
        createdAt=datetime.now(),
        updatedBy=type("U", (), {"id": "", "type": "", "name": "", "accountId": "", "accountType": ""})(),
        updatedAt=datetime.now(),
    )


def test_groups_helpers():
    g1 = _g(None)
    g2 = _g("root")
    gr = Groups([g1, g2])
    assert gr.get_group_by_id("1") is g1
    assert gr.get_group_by_name("Root") is g1
    assert gr.find_groups_by_name("Root") == [g1, g2]
    assert gr.get_child_groups("root") is None
    assert gr.get_root_groups() == [g1]
