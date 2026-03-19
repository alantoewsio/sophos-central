"""Tests for central.db."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import central.db as db


def test_json_serial_and_to_json():
    class WithId:
        id = "z"

    assert json.loads(json.dumps(WithId(), default=db._json_serial)) == "z"

    class Plain:
        def __init__(self):
            self.a = 1
            self._b = 2

    d = json.loads(json.dumps(Plain(), default=db._json_serial))
    assert d == {"a": 1}

    with pytest.raises(TypeError):
        json.dumps(object(), default=db._json_serial)

    assert db._to_json(None) is None
    assert "a" in db._to_json({"a": 1})

    class Cyclic:
        pass

    c = Cyclic()
    c.r = c
    out = db._to_json(c)
    assert isinstance(out, str)


def test_get_and_get_nested():
    assert db._get(SimpleNamespace(x=1), "x") == 1
    assert db._get({"x": 2}, "x") == 2
    assert db._get({}, "x", 3) == 3
    assert db._get_nested(SimpleNamespace(a=SimpleNamespace(b=9)), "a", "b") == 9
    assert db._get_nested({"a": {}}, "a", "b", default=0) == 0


def test_get_connection_and_init_schema(tmp_path: Path):
    p = tmp_path / "d.db"
    conn = db.get_connection(p)
    db.init_schema(conn)
    conn.execute("SELECT 1 FROM tenants LIMIT 1")
    conn.close()


def test_get_new_alert_ids_and_run_summary_and_latest_raised(db_conn):
    sync_id = "s1"
    tid = "tenant1"
    db_conn.execute(
        """INSERT INTO alerts (id, tenant_id, raised_at, first_sync, last_sync, sync_id)
           VALUES (?, ?, ?, ?, ?, ?)""",
        ("a1", tid, "2024-01-01T00:00:00Z", "t", "t", sync_id),
    )
    db_conn.commit()
    assert db.get_new_alert_ids(db_conn, sync_id, tid) == ["a1"]
    assert "alerts" in db.get_run_summary(db_conn, sync_id)
    assert db.get_latest_alert_raised_at(db_conn, tid) == "2024-01-01T00:00:00Z"
    assert db.get_latest_alert_raised_at(db_conn, "none") is None


def test_migrate_sync_columns(tmp_path: Path):
    p = tmp_path / "mig.db"
    c = sqlite3.connect(p)
    c.execute(
        """CREATE TABLE tenants (
            id TEXT PRIMARY KEY,
            added_timestamp TEXT,
            updated_timestamp TEXT,
            update_id TEXT
        )"""
    )
    c.commit()
    db._migrate_sync_columns(c)
    cols = {row[1] for row in c.execute("PRAGMA table_info(tenants)")}
    assert "first_sync" in cols
    assert "last_sync" in cols
    assert "sync_id" in cols
    c.close()


def test_ensure_sync_columns(tmp_path: Path):
    p = tmp_path / "ens.db"
    c = sqlite3.connect(p)
    for name in (
        "tenants",
        "firewalls",
        "licenses",
        "license_subscriptions",
        "alerts",
        "alert_details",
        "firmware_upgrades",
        "firmware_versions",
    ):
        c.execute(f"CREATE TABLE {name} (id TEXT PRIMARY KEY)")
    c.commit()
    db._ensure_sync_columns(c)
    cols = {row[1] for row in c.execute("PRAGMA table_info(firewalls)")}
    assert "first_sync" in cols
    c.close()


def test_drop_synced_at_column(tmp_path: Path):
    p = tmp_path / "drop.db"
    c = sqlite3.connect(p)
    try:
        c.execute(
            "CREATE TABLE firewalls (id TEXT PRIMARY KEY, synced_at TEXT, tenant_id TEXT, serial_number TEXT)"
        )
    except sqlite3.OperationalError:
        pytest.skip("minimal schema")
    c.commit()
    db._drop_synced_at_column(c)
    cols = [row[1] for row in c.execute("PRAGMA table_info(firewalls)")]
    assert "synced_at" not in cols
    c.close()


def test_upsert_tenant_dict_and_contact_branches(db_conn):
    db.upsert_tenant(
        db_conn,
        {
            "id": "t1",
            "showAs": "S",
            "name": "N",
            "dataGeography": "g",
            "dataRegion": "r",
            "billingType": "b",
            "partner": {"id": "p1"},
            "organization": {"id": "o1"},
            "apiHost": "h",
            "status": "ok",
            "contact": SimpleNamespace(__dict__={"email": "e"}),
            "externalIds": [1],
            "products": [{"code": "FW"}, "RAW"],
        },
        update_id="u1",
        run_timestamp="ts",
    )

    class BadContact:
        def __getattribute__(self, n):
            if n == "__dict__":
                raise RuntimeError("x")
            return super().__getattribute__(n)

    db.upsert_tenant(
        db_conn,
        {
            "id": "t2",
            "name": "N2",
            "contact": BadContact(),
        },
        update_id="u1",
        run_timestamp="ts",
    )
    db_conn.commit()


def test_upsert_firewall(db_conn):
    fw = SimpleNamespace(
        id="fw1",
        tenant=SimpleNamespace(id="t1"),
        serialNumber="SN1",
        group=SimpleNamespace(id="g", name="G"),
        hostname="h",
        name="n",
        externalIpv4Addresses=["1.1.1.1"],
        firmwareVersion="v1",
        model="m",
        status=SimpleNamespace(
            managingStatus="approved",
            reportingStatus="approved",
            connected=True,
            suspended=True,
        ),
        stateChangedAt="s",
        capabilities=["a"],
        geoLocation=SimpleNamespace(latitude="1", longitude="2"),
        createdAt="c",
        updatedAt="u",
    )
    db.upsert_firewall(db_conn, fw, update_id="u", run_timestamp="ts")

    fw2 = SimpleNamespace(
        id="fw2",
        tenant={"id": "t1"},
        serialNumber="SN2",
        group=None,
        status=None,
        geoLocation=None,
    )
    for k in (
        "hostname",
        "name",
        "externalIpv4Addresses",
        "firmwareVersion",
        "model",
        "stateChangedAt",
        "capabilities",
        "createdAt",
        "updatedAt",
    ):
        setattr(fw2, k, None)
    db.upsert_firewall(db_conn, fw2, update_id="u", run_timestamp="ts")
    db_conn.commit()


def test_upsert_license_and_subscriptions(db_conn):
    sub = SimpleNamespace(
        id="sub1",
        licenseIdentifier="L1",
        product=SimpleNamespace(code="c", name="n"),
        startDate="s",
        endDate="e",
        perpetual=True,
        type="term",
        quantity=1,
        usage=SimpleNamespace(
            current=SimpleNamespace(count=5, date=datetime(2024, 1, 1, tzinfo=timezone.utc))
        ),
        unlimited=True,
    )
    lic = SimpleNamespace(
        serialNumber="SER",
        tenant=SimpleNamespace(id="t1"),
        partner=SimpleNamespace(id="p1"),
        organization=SimpleNamespace(id="o1"),
        model="m",
        modelType="hardware",
        licenses=[sub],
        lastSeenAt="ls",
    )
    db.upsert_license(db_conn, lic, update_id="u", run_timestamp="ts")

    lic2 = SimpleNamespace(
        serialNumber="SER2",
        tenant=None,
        partner=None,
        organization=None,
        model="m",
        modelType="virtual",
        licenses=[],
    )
    db.upsert_license(
        db_conn, lic2, tenant_id="tx", partner_id="px", update_id="u", run_timestamp="ts"
    )
    db_conn.commit()


def test_upsert_alert_and_detail(db_conn):
    alert = {
        "id": "al1",
        "tenant": {"id": "t1"},
        "category": "c",
        "description": "d",
        "groupKey": "g",
        "product": "p",
        "raisedAt": "r",
        "severity": "high",
        "type": "t",
        "allowedActions": [],
        "managedAgent": {"id": "1", "type": "x"},
        "person": {"id": "2"},
    }
    db.upsert_alert(db_conn, alert, update_id="u", run_timestamp="ts")
    db.upsert_alert_detail(db_conn, alert, tenant_id="t1", update_id="u", run_timestamp="ts")
    db_conn.commit()


def test_upsert_firmware_upgrade_and_version(db_conn):
    up = SimpleNamespace(
        id="fwu",
        serialNumber="SN",
        firmwareVersion="v0",
        upgradeToVersion=[{"v": "1"}],
    )
    db.upsert_firmware_upgrade(
        db_conn, up, tenant_id="t1", update_id="u", run_timestamp="ts"
    )
    up2 = SimpleNamespace(id="fwu2", serialNumber="SN2", upgradeToVersion=[])
    db.upsert_firmware_upgrade(
        db_conn, up2, tenant_id="t1", update_id="u", run_timestamp="ts"
    )

    fv = SimpleNamespace(version="19.0", size="1M", bugs=["b"], news=["n"])
    db.upsert_firmware_version(db_conn, fv, update_id="u", run_timestamp="ts")
    db_conn.commit()


@patch("central.db.logger")
def test_init_schema_logs(mock_log, tmp_path: Path):
    c = db.get_connection(tmp_path / "z.db")
    db.init_schema(c)
    mock_log.debug.assert_called()
