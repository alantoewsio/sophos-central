"""Additional central.db coverage."""

import json
from types import SimpleNamespace

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


def test_serialize_cell_bytes_and_memoryview():
    assert db._serialize_cell(b"ab") == "ab"
    assert db._serialize_cell(memoryview(b"x")) == "x"


def test_log_data_row_changes_no_context_and_both_none(db_conn):
    db.upsert_tenant(
        db_conn,
        {"id": "lc1", "name": "N"},
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="t",
    )
    row = db_conn.execute("SELECT * FROM tenants WHERE id=?", ("lc1",)).fetchone()
    n0 = db_conn.execute("SELECT COUNT(*) FROM sync_change_events").fetchone()[0]
    db.log_data_row_changes(db_conn, "tenants", {"id": "lc1"}, row, None)
    assert db_conn.execute("SELECT COUNT(*) FROM sync_change_events").fetchone()[0] == n0
    with db.sync_change_logging("s", "oauth-cid", "ts"):
        db.log_data_row_changes(db_conn, "tenants", {"id": "lc1"}, row, None)
        n_mid = db_conn.execute("SELECT COUNT(*) FROM sync_change_events").fetchone()[0]
        db.log_data_row_changes(db_conn, "tenants", {"id": "none"}, None, None)
    n_final = db_conn.execute("SELECT COUNT(*) FROM sync_change_events").fetchone()[0]
    assert n_mid > n0
    assert n_final == n_mid


def test_stale_deletes_and_changelog_rows(db_conn):
    """Exercise stale-row helpers and cascade under sync_change_logging."""
    c, ts, sid = "oauth-cid", "2025-01-01T00:00:00+00:00", "chg-1"
    ins_t = """
        INSERT INTO tenants (id, show_as, name, updated_at, first_sync, last_sync, sync_id, client_id)
        VALUES (?, ?, ?, 'u', 'f', 'l', 'old', ?)
    """
    for tid, name in [("t1", "A"), ("t2", "B")]:
        db_conn.execute(ins_t, (tid, tid, name, c))
    ins_fw = """
        INSERT INTO firewalls (
            id, tenant_id, serial_number, connected, suspended,
            first_sync, last_sync, sync_id, client_id
        ) VALUES (?, ?, ?, 0, 0, 'f', 'l', 'old', ?)
    """
    for fid, sn in [("fw1", "SN1"), ("fw2", "SN2")]:
        db_conn.execute(ins_fw, (fid, "t1", sn, c))
    for sn, tid in [("L1", "t1"), ("L2", "t1")]:
        db_conn.execute(
            """
            INSERT INTO licenses (
                serial_number, tenant_id, partner_id, organization_id, model, model_type,
                last_seen_at, first_sync, last_sync, sync_id, client_id
            ) VALUES (?, ?, NULL, NULL, 'm', 'hardware', NULL, 'f', 'l', 'old', ?)
            """,
            (sn, tid, c),
        )
    db_conn.execute(
        """
        INSERT INTO licenses (
            serial_number, tenant_id, partner_id, organization_id, model, model_type,
            last_seen_at, first_sync, last_sync, sync_id, client_id
        ) VALUES ('PL1', NULL, 'p1', NULL, 'm', 'hardware', NULL, 'f', 'l', 'old', ?)
        """,
        (c,),
    )
    for fid in ("fw1", "fw2"):
        db_conn.execute(
            """
            INSERT INTO firmware_upgrades (
                firewall_id, tenant_id, serial_number, current_version,
                upgrade_to_versions_json, first_sync, last_sync, sync_id, client_id
            ) VALUES (?, 't1', 'SNx', '1.0', '[]', 'f', 'l', 'old', ?)
            """,
            (fid, c),
        )
    for ver in ("v_keep", "v_drop"):
        db_conn.execute(
            """
            INSERT INTO firmware_versions (
                version, size, bugs_json, news_json, first_sync, last_sync, sync_id, client_id
            ) VALUES (?, '1', '[]', '[]', 'f', 'l', 'old', ?)
            """,
            (ver, c),
        )
    for gid in ("g1", "g2"):
        db_conn.execute(
            """
            INSERT INTO firewall_groups (
                id, tenant_id, name, locked_by_managing_account,
                first_sync, last_sync, sync_id, client_id
            ) VALUES (?, 't1', ?, 0, 'f', 'l', 'old', ?)
            """,
            (gid, gid, c),
        )
    db_conn.execute(
        """
        INSERT INTO firewall_group_sync_status (
            group_id, firewall_id, tenant_id, status, last_updated_at,
            first_sync, last_sync, sync_id, client_id
        ) VALUES ('g1', 'fw1', 't1', 'ok', 'x', 'f', 'l', 'old', ?),
                 ('g1', 'fw2', 't1', 'ok', 'x', 'f', 'l', 'old', ?)
        """,
        (c, c),
    )
    for fid in ("fw1", "fw2"):
        db_conn.execute(
            """
            INSERT INTO mdr_threat_feed_sync (
                firewall_id, tenant_id, transaction_id, poll_status,
                transaction_status, transaction_result, response_json, detail_message,
                first_sync, last_sync, sync_id, client_id
            ) VALUES (?, 't1', NULL, NULL, NULL, NULL, NULL, NULL, 'f', 'l', 'old', ?)
            """,
            (fid, c),
        )
    db_conn.commit()

    with db.sync_change_logging(sid, c, ts):
        db.delete_stale_firewalls_for_tenant(
            db_conn, client_id=c, tenant_id="t1", keep_ids={"fw1"}, api_ok=True
        )
        db.delete_stale_licenses_for_tenant(
            db_conn,
            client_id=c,
            tenant_id="t1",
            keep_serials={"L1"},
            api_ok=True,
        )
        db.delete_stale_partner_licenses(
            db_conn,
            client_id=c,
            partner_id="p1",
            keep_serials=set(),
            api_ok=True,
        )
        db.delete_stale_firmware_upgrades_for_tenant(
            db_conn,
            client_id=c,
            tenant_id="t1",
            keep_firewall_ids={"fw1"},
            api_ok=True,
        )
        db.delete_stale_firmware_versions_for_client(
            db_conn,
            client_id=c,
            keep_versions={"v_keep"},
            prune=True,
        )
        db.delete_stale_firewall_groups_for_tenant(
            db_conn,
            client_id=c,
            tenant_id="t1",
            keep_ids={"g1"},
            api_ok=True,
        )
        db.delete_stale_firewall_group_sync_status_for_tenant(
            db_conn,
            client_id=c,
            tenant_id="t1",
            keep_pairs={("g1", "fw1")},
            api_ok=True,
        )
        db.delete_stale_mdr_for_tenant(
            db_conn,
            client_id=c,
            tenant_id="t1",
            keep_firewall_ids={"fw1"},
            sync_mdr=True,
            api_ok=True,
        )
        db.delete_stale_tenants_for_partner(
            db_conn, client_id=c, keep_tenant_ids={"t1"}, api_ok=True
        )

    ev = db_conn.execute(
        "SELECT COUNT(*) FROM sync_change_events WHERE sync_id=?", (sid,)
    ).fetchone()[0]
    assert ev >= 5
    assert db_conn.execute("SELECT COUNT(*) FROM firewalls WHERE id='fw2'").fetchone()[0] == 0
    assert db_conn.execute("SELECT COUNT(*) FROM tenants WHERE id='t2'").fetchone()[0] == 0


def test_delete_stale_firewalls_api_off_noop(db_conn):
    db_conn.execute(
        """
        INSERT INTO tenants (id, show_as, name, updated_at, first_sync, last_sync, sync_id, client_id)
        VALUES ('tx', 'tx', 'x', 'u', 'f', 'l', 'o', 'oauth-cid')
        """
    )
    db_conn.execute(
        """
        INSERT INTO firewalls (
            id, tenant_id, serial_number, connected, suspended,
            first_sync, last_sync, sync_id, client_id
        ) VALUES ('fx', 'tx', 'S', 0, 0, 'f', 'l', 'o', 'oauth-cid')
        """
    )
    db_conn.commit()
    db.delete_stale_firewalls_for_tenant(
        db_conn,
        client_id="oauth-cid",
        tenant_id="tx",
        keep_ids=set(),
        api_ok=False,
    )
    assert db_conn.execute("SELECT COUNT(*) FROM firewalls WHERE id='fx'").fetchone()[0] == 1


def test_delete_stale_empty_keep_sets_prune_firewalls(db_conn):
    db_conn.execute(
        """
        INSERT INTO tenants (id, show_as, name, updated_at, first_sync, last_sync, sync_id, client_id)
        VALUES ('te', 'te', 'e', 'u', 'f', 'l', 'o', 'oauth-cid')
        """
    )
    db_conn.execute(
        """
        INSERT INTO firewalls (
            id, tenant_id, serial_number, connected, suspended,
            first_sync, last_sync, sync_id, client_id
        ) VALUES ('fe', 'te', 'S', 0, 0, 'f', 'l', 'o', 'oauth-cid')
        """
    )
    db_conn.commit()
    with db.sync_change_logging("s", "oauth-cid", "t"):
        db.delete_stale_firewalls_for_tenant(
            db_conn,
            client_id="oauth-cid",
            tenant_id="te",
            keep_ids=set(),
            api_ok=True,
        )
    assert db_conn.execute("SELECT COUNT(*) FROM firewalls").fetchone()[0] == 0


def test_upsert_license_removes_stale_subscription_with_changelog(db_conn):
    sub_a = SimpleNamespace(
        id="sub_a",
        licenseIdentifier="L",
        product=None,
        startDate=None,
        endDate=None,
        perpetual=False,
        type="t",
        quantity=1,
        usage=None,
        unlimited=False,
    )
    sub_b = SimpleNamespace(
        id="sub_b",
        licenseIdentifier="L2",
        product=None,
        startDate=None,
        endDate=None,
        perpetual=False,
        type="t",
        quantity=1,
        usage=None,
        unlimited=False,
    )
    lic_both = SimpleNamespace(
        serialNumber="SRM",
        tenant=SimpleNamespace(id="t1"),
        partner=None,
        organization=None,
        model="m",
        modelType="hardware",
        licenses=[sub_a, sub_b],
    )
    lic_one = SimpleNamespace(
        serialNumber="SRM",
        tenant=SimpleNamespace(id="t1"),
        partner=None,
        organization=None,
        model="m",
        modelType="hardware",
        licenses=[sub_a],
    )
    db.upsert_tenant(
        db_conn,
        {"id": "t1", "name": "T"},
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="r",
    )
    with db.sync_change_logging("up", "oauth-cid", "ts"):
        db.upsert_license(
            db_conn,
            lic_both,
            client_id="oauth-cid",
            update_id="u",
            run_timestamp="r",
        )
        db.upsert_license(
            db_conn,
            lic_one,
            client_id="oauth-cid",
            update_id="u2",
            run_timestamp="r2",
        )
    assert (
        db_conn.execute(
            "SELECT COUNT(*) FROM license_subscriptions WHERE id='sub_b'"
        ).fetchone()[0]
        == 0
    )
    del_ev = db_conn.execute(
        "SELECT COUNT(*) FROM sync_change_events WHERE operation='delete' AND table_name='license_subscriptions'"
    ).fetchone()[0]
    assert del_ev >= 1


def test_update_firewall_group_items_and_mdr_with_changelog(db_conn):
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
            "id": "gm",
            "name": "G",
            "parentGroup": None,
            "lockedByManagingAccount": False,
            "firewalls": None,
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
    with db.sync_change_logging("lg", "oauth-cid", "ts"):
        db.update_firewall_group_items_json_from_sync(
            db_conn, "gm", [{"id": "f1"}, {"id": "f2"}]
        )
        db.upsert_mdr_threat_feed_sync(
            db_conn,
            firewall_id="mf1",
            tenant_id="t1",
            transaction_id="t1",
            poll_status="p",
            transaction_status=None,
            transaction_result=None,
            response_json=None,
            detail_message=None,
            client_id="oauth-cid",
            update_id="u",
            run_timestamp="r",
        )
        db.upsert_mdr_threat_feed_sync(
            db_conn,
            firewall_id="mf1",
            tenant_id="t1",
            transaction_id="t2",
            poll_status="done",
            transaction_status=None,
            transaction_result=None,
            response_json=None,
            detail_message=None,
            client_id="oauth-cid",
            update_id="u2",
            run_timestamp="r2",
        )
    upd_fg = db_conn.execute(
        "SELECT COUNT(*) FROM sync_change_events WHERE table_name='firewall_groups' AND operation='update'"
    ).fetchone()[0]
    assert upd_fg >= 1
    mdr_ev = db_conn.execute(
        "SELECT COUNT(*) FROM sync_change_events WHERE table_name='mdr_threat_feed_sync'"
    ).fetchone()[0]
    assert mdr_ev >= 1
