"""Additional central.db coverage."""

import json

import central.db as db


def test_upsert_tenant_contact_exception_path(db_conn):
    """Contact object whose __dict__ is not dict-like triggers except str(contact)."""
    class BadContact:
        @property
        def __dict__(self):
            return [1, 2, 3]

    db.upsert_tenant(
        db_conn,
        {
            "id": "tc",
            "name": "n",
            "contact": BadContact(),
        },
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="t",
    )


def test_upsert_tenant_contact_dict_without_get(db_conn):
    class M:
        __dict__ = {"x": 1}

    db.upsert_tenant(
        db_conn,
        {"id": "tx", "name": "n", "contact": M()},
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="t",
    )


def test_scalar_text_isoformat_raises(db_conn):
    class BadDate:
        def isoformat(self):
            raise ValueError("nope")

    db.upsert_tenant(
        db_conn,
        {"id": "t1", "name": "T"},
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="r",
    )
    db.upsert_firewall_group(
        db_conn,
        {
            "id": "giso",
            "name": "N",
            "parentGroup": None,
            "lockedByManagingAccount": False,
            "firewalls": None,
            "configImport": None,
            "createdBy": None,
            "updatedBy": None,
            "createdAt": BadDate(),
            "updatedAt": None,
        },
        tenant_id="t1",
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="r",
    )
    row = db_conn.execute(
        "SELECT created_at FROM firewall_groups WHERE id=?", ("giso",)
    ).fetchone()
    assert row[0] is not None


def test_upsert_firewall_group_and_sync_status(db_conn):
    db.upsert_tenant(
        db_conn,
        {"id": "t1", "name": "T"},
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="r",
    )
    g = {
        "id": "gg1",
        "name": "Grp",
        "parentGroup": {"id": "p1"},
        "lockedByManagingAccount": True,
        "firewalls": {"total": 1, "itemsCount": 1, "items": [{"id": "fw1"}]},
        "configImport": None,
        "createdBy": None,
        "updatedBy": None,
        "createdAt": "2020-01-01",
        "updatedAt": None,
    }
    db.upsert_firewall_group(
        db_conn,
        g,
        tenant_id="t1",
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="r",
    )
    db.upsert_firewall_group_sync_status(
        db_conn,
        group_id="gg1",
        firewall_id="fw1",
        tenant_id="t1",
        status="inSync",
        last_updated_at="2020-02-02",
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="r",
    )
    assert db_conn.execute(
        "SELECT name FROM firewall_groups WHERE id=?", ("gg1",)
    ).fetchone()[0] == "Grp"
    assert (
        db_conn.execute(
            "SELECT status FROM firewall_group_sync_status WHERE group_id=?",
            ("gg1",),
        ).fetchone()[0]
        == "inSync"
    )


def test_update_firewall_group_items_json_from_sync(db_conn):
    db.upsert_tenant(
        db_conn,
        {"id": "t1", "name": "T"},
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="r",
    )
    db.upsert_firewall_group(
        db_conn,
        {
            "id": "gx",
            "name": "G",
            "parentGroup": None,
            "lockedByManagingAccount": False,
            "firewalls": {"total": 2, "itemsCount": 2},
            "configImport": None,
            "createdBy": None,
            "updatedBy": None,
            "createdAt": "2020-01-01",
            "updatedAt": None,
        },
        tenant_id="t1",
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="r",
    )
    assert (
        db_conn.execute(
            "SELECT firewalls_items_json FROM firewall_groups WHERE id=?",
            ("gx",),
        ).fetchone()[0]
        is None
    )
    db.update_firewall_group_items_json_from_sync(
        db_conn, "gx", [{"id": "a"}, {"id": "b"}]
    )
    row = db_conn.execute(
        "SELECT firewalls_items_json, firewalls_items_count, firewalls_total "
        "FROM firewall_groups WHERE id=?",
        ("gx",),
    ).fetchone()
    assert json.loads(row[0]) == [{"id": "a"}, {"id": "b"}]
    assert row[1] == 2 and row[2] == 2


def test_upsert_license_usage_date_string(db_conn):
    from types import SimpleNamespace

    sub = SimpleNamespace(
        id="s1",
        licenseIdentifier="L",
        product=None,
        startDate="s",
        endDate=None,
        perpetual=False,
        type="term",
        quantity=1,
        usage=SimpleNamespace(
            current=SimpleNamespace(count=1, date="2024-01-01")
        ),
        unlimited=False,
    )
    lic = SimpleNamespace(
        serialNumber="SER3",
        tenant=None,
        partner=None,
        organization=None,
        model="m",
        modelType="hardware",
        licenses=[sub],
    )
    db.upsert_license(
        db_conn, lic, client_id="oauth-cid", update_id="u", run_timestamp="t"
    )
