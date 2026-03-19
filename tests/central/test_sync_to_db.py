"""Tests for central.sync_to_db."""

from __future__ import annotations

import io
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from central.classes import ReturnState
from central.sync_to_db import (
    CentralSyncAuthError,
    CredentialsSyncResult,
    SyncProgress,
    _cred_sources_from_args,
    _format_duration,
    _from_time_after,
    _quiet_sync_cli_loggers,
    ensure_tenant_record,
    export_db_to_xlsx,
    get_creds,
    get_creds_from_env_file,
    parse_args,
    sync_client_credentials_to_database,
    sync_partner,
    sync_tenant,
)


def test_format_duration():
    assert "ms" in _format_duration(0.5)
    assert "s" in _format_duration(2.0)


def test_from_time_after_ok_and_bad():
    assert _from_time_after("2024-01-01T00:00:00Z") is not None
    assert _from_time_after("not-a-date") is None


@patch("central.sync_to_db.logger")
def test_from_time_after_warning_on_parse_error(mock_log):
    assert _from_time_after("bad") is None
    mock_log.warning.assert_called_once()


def test_get_creds_from_env_file(tmp_path: Path):
    p = tmp_path / "c.env"
    p.write_text("CENTRAL-CLIENT-ID=a\nCENTRAL-CLIENT-SECRET=b\n", encoding="utf-8")
    c = get_creds_from_env_file(p)
    assert c["CENTRAL-CLIENT-ID"] == "a"


def test_get_creds_from_env_file_errors(tmp_path: Path):
    with pytest.raises(ValueError, match="not found"):
        get_creds_from_env_file(tmp_path / "nope")
    bad = tmp_path / "bad.env"
    bad.write_text("x=1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid"):
        get_creds_from_env_file(bad)


def test_central_sync_auth_error():
    e = CentralSyncAuthError("m")
    assert e.message == "m"


def test_credentials_sync_result():
    r = CredentialsSyncResult("s", {}, {}, 1.0)
    assert r.sync_id == "s"


def test_cred_sources_from_args(tmp_path: Path):
    p = tmp_path / "e.env"
    p.write_text("CENTRAL-CLIENT-ID=x\nCENTRAL-CLIENT-SECRET=y\n", encoding="utf-8")
    args = SimpleNamespace(client_id=None, client_secret=None, env=[p])
    assert _cred_sources_from_args(args) == [("x", "y")]
    args2 = SimpleNamespace(client_id=" i ", client_secret=" s ", env=None)
    assert _cred_sources_from_args(args2) == [("i", "s")]


@patch("central.sync_to_db.get_creds")
def test_cred_sources_from_args_default_creds(mock_get_creds, tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    mock_get_creds.return_value = {"CENTRAL-CLIENT-ID": "def", "CENTRAL-CLIENT-SECRET": "sec"}
    args = SimpleNamespace(client_id=None, client_secret=None, env=None)
    assert _cred_sources_from_args(args) == [("def", "sec")]


def test_sync_progress_non_tty():
    sp = SyncProgress()
    sp._visible = False
    sp.set_total(5)
    sp.update("msg", 1)
    sp.clear()


def test_sync_progress_tty(capsys):
    sp = SyncProgress()
    sp._visible = True
    sp._total = 10
    sp._current = 5
    sp._message = "hello world " * 20
    sp._render()
    sp.clear()


def test_sync_progress_render_with_total_zero():
    sp = SyncProgress()
    sp._visible = True
    sp._total = 0
    sp._current = 0
    sp._message = "idle"
    sp._render()


def test_sync_progress_update_with_current_param():
    """Cover 165-168: update(message, current=N) and update(message) with _visible True."""
    sp = SyncProgress()
    sp._visible = True
    sp.set_total(10)
    sp.update("only message")  # branch when current is None (165->167)
    assert sp._message == "only message"
    sp.update("syncing", current=3)
    assert sp._current == 3
    assert sp._message == "syncing"


def test_quiet_sync_loggers():
    with _quiet_sync_cli_loggers(False):
        pass
    with _quiet_sync_cli_loggers(True):
        pass


def test_ensure_tenant_record(db_conn):
    ensure_tenant_record(
        db_conn, "w1", name="N", update_id="u", run_timestamp="t"
    )


def test_export_db_to_xlsx(db_conn, tmp_path: Path):
    db_conn.execute(
        "INSERT INTO tenants (id, name, updated_at, first_sync, last_sync, sync_id) VALUES (?,?,?,?,?,?)",
        ("t", "n", "u", "f", "l", "s"),
    )
    db_conn.commit()
    out = tmp_path / "o.xlsx"
    export_db_to_xlsx(db_conn, out)
    assert out.exists()


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_firewalls")
def test_sync_partner_minimal(
    mock_gfw, mock_lic, mock_alerts, mock_get_alert, mock_fw_up,
    db_conn,
):
    mock_gfw.return_value = ReturnState(success=False, message="x")
    mock_lic.return_value = ReturnState(success=False, message="x")
    mock_alerts.return_value = ReturnState(success=False, message="x")
    mock_fw_up.return_value = ReturnState(success=False, message="x")
    central = MagicMock()
    central.get_tenants.return_value = ReturnState(success=False, message="no tenants")
    sync_partner(
        db_conn,
        central,
        update_id="u",
        run_timestamp="ts",
        progress=None,
    )
    tenant = SimpleNamespace(
        id="t1", name="T", apiHost="https://h/"
    )
    central.get_tenants.return_value = [tenant]
    mock_gfw.return_value = []
    mock_lic.return_value = []
    mock_alerts.return_value = []
    mock_get_new = patch(
        "central.sync_to_db.get_new_alert_ids", return_value=[]
    )
    mock_latest = patch(
        "central.sync_to_db.get_latest_alert_raised_at", return_value=None
    )
    mock_fw_up.return_value = SimpleNamespace(
        success=True,
        firewalls=[],
        firmwareVersions=[],
    )
    with mock_get_new, mock_latest:
        sync_partner(
            db_conn,
            central,
            update_id="u2",
            run_timestamp="ts",
            elapsed_by_table={},
            progress=SyncProgress(),
        )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_firewalls")
def test_sync_partner_with_alerts_and_details(
    mock_gfw, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn
):
    central = MagicMock()
    central.whoami = SimpleNamespace(id="p1")
    tenant = SimpleNamespace(id="t1", name="T", apiHost="https://h/")
    central.get_tenants.return_value = [tenant]
    fw_obj = SimpleNamespace(
        id="fw1",
        serialNumber="SN1",
        tenant=SimpleNamespace(id="t1"),
        group=None,
        status=None,
    )
    mock_gfw.return_value = [fw_obj]
    mock_lic.return_value = []
    mock_alerts.return_value = [SimpleNamespace(id="a1")]
    mock_get_alert.return_value = {"id": "a1", "category": "c"}
    mock_fw_up.return_value = SimpleNamespace(
        success=True,
        firewalls=[SimpleNamespace(id="fw1", serialNumber="S", upgradeToVersion=[])],
        firmwareVersions=[],
    )
    with patch("central.sync_to_db.get_new_alert_ids", return_value=["a1"]):
        with patch(
            "central.sync_to_db.get_latest_alert_raised_at", return_value=None
        ):
            sync_partner(
                db_conn,
                central,
                update_id="u3",
                run_timestamp="ts",
                progress=None,
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_firewalls")
def test_sync_partner_licenses_fail_alerts_fail(
    mock_gfw, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn
):
    """Firewalls success (empty list) so firewalls is bound; licenses and alerts fail."""
    central = MagicMock()
    tenant = SimpleNamespace(id="t1", name="T", apiHost="https://h/")
    central.get_tenants.return_value = [tenant]
    mock_gfw.return_value = []
    mock_lic.side_effect = [
        ReturnState(success=False, message="partner lic"),
        ReturnState(success=False, message="tenant lic"),
    ]
    mock_alerts.return_value = ReturnState(success=False, message="al")
    mock_fw_up.return_value = ReturnState(success=False, message="fwup")
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_partner(db_conn, central, update_id="u", run_timestamp="ts", progress=None)


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_firewalls")
def test_sync_partner_licenses_and_firmware_success(mock_gfw, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn):
    """Cover 354, 455, 470, 507: tenant licenses success, firmware success with versions, partner licenses success."""
    lic = SimpleNamespace(
        serialNumber="S",
        tenant=SimpleNamespace(id="t1"),
        partner=SimpleNamespace(id="p"),
        organization=SimpleNamespace(id="o"),
        model="m",
        modelType="hardware",
        licenses=[],
    )
    central = MagicMock()
    central.whoami = SimpleNamespace(id="p1")
    tenant = SimpleNamespace(id="t1", name="T", apiHost="https://h/")
    central.get_tenants.return_value = [tenant]
    fw_obj = SimpleNamespace(
        id="fw1", serialNumber="SN1", tenant=SimpleNamespace(id="t1"),
        group=None, status=None,
    )
    mock_gfw.return_value = [fw_obj]
    mock_lic.side_effect = [[lic], [lic]]
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(
        success=True,
        firewalls=[SimpleNamespace(id="fw1", serialNumber="SN1", upgradeToVersion=["v2"])],
        firmwareVersions=[SimpleNamespace(version="v2", size="1", bugs=[], news=[])],
    )
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            progress = SyncProgress()
            progress._visible = True
            sync_partner(
                db_conn,
                central,
                update_id="u",
                run_timestamp="ts",
                progress=progress,
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_firewalls")
def test_sync_partner_with_latest_raised_from_time(mock_gfw, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn):
    central = MagicMock()
    tenant = SimpleNamespace(id="t1", name="T", apiHost="https://h/")
    central.get_tenants.return_value = [tenant]
    mock_gfw.return_value = []
    mock_lic.return_value = []
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(success=True, firewalls=[], firmwareVersions=[])
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value="2024-06-01T12:00:00Z"):
            sync_partner(db_conn, central, update_id="u", run_timestamp="ts", progress=None)


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_firewalls")
def test_sync_tenant_paths(mock_gfw, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn):
    central = MagicMock()
    central.whoami = SimpleNamespace(id="t1", data_region_url=lambda: "https://d/")
    mock_gfw.return_value = ReturnState(success=False, message="e")
    mock_lic.return_value = ReturnState(success=False, message="e")
    mock_alerts.return_value = ReturnState(success=False, message="e")
    mock_fw_up.return_value = ReturnState(success=False, message="e")
    sync_tenant(db_conn, central, update_id="u", run_timestamp="ts", progress=None)

    mock_gfw.return_value = []
    mock_lic.return_value = []
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(success=True, firewalls=[], firmwareVersions=[])
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_tenant(
                db_conn,
                central,
                update_id="u2",
                run_timestamp="ts",
                progress=SyncProgress(),
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_firewalls")
def test_sync_tenant_with_latest_raised_and_alert_details(
    mock_gfw, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn
):
    central = MagicMock()
    central.whoami = SimpleNamespace(id="t1", data_region_url=lambda: "https://d/")
    mock_gfw.return_value = [SimpleNamespace(id="f1", serialNumber="S", tenant=SimpleNamespace(id="t1"))]
    mock_lic.return_value = []
    mock_alerts.return_value = [{"id": "a1"}]
    mock_get_alert.return_value = {"id": "a1", "category": "c"}
    mock_fw_up.return_value = SimpleNamespace(
        success=True,
        firewalls=[SimpleNamespace(id="f1", serialNumber="S", upgradeToVersion=[])],
        firmwareVersions=[],
    )
    with patch("central.sync_to_db.get_new_alert_ids", return_value=["a1"]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value="2024-01-01T00:00:00Z"):
            sync_tenant(db_conn, central, update_id="u", run_timestamp="ts", progress=None)


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_firewalls")
def test_sync_tenant_with_progress_and_firmware_success(
    mock_gfw, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn
):
    """Cover 538->540, 585, 671, 682: progress updates and firmware success with firewalls + versions."""
    lic = SimpleNamespace(
        serialNumber="S",
        tenant=SimpleNamespace(id="t1"),
        partner=SimpleNamespace(id="p"),
        organization=SimpleNamespace(id="o"),
        model="m",
        modelType="hardware",
        licenses=[],
    )
    central = MagicMock()
    central.whoami = SimpleNamespace(id="t1", data_region_url=lambda: "https://d/")
    fw = SimpleNamespace(id="f1", serialNumber="SN", tenant=SimpleNamespace(id="t1"))
    mock_gfw.return_value = [fw]
    mock_lic.return_value = [lic]
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(
        success=True,
        firewalls=[SimpleNamespace(id="f1", serialNumber="SN", upgradeToVersion=["v2"])],
        firmwareVersions=[SimpleNamespace(version="v2", size="1", bugs=[], news=[])],
    )
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            progress = SyncProgress()
            progress._visible = True
            sync_tenant(
                db_conn,
                central,
                update_id="u",
                run_timestamp="ts",
                progress=progress,
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_firewalls")
def test_sync_tenant_licenses_fail(mock_gfw, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn):
    central = MagicMock()
    central.whoami = SimpleNamespace(id="t1", data_region_url=lambda: "https://d/")
    mock_gfw.return_value = []
    mock_lic.return_value = ReturnState(success=False, message="lic fail")
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(success=True, firewalls=[], firmwareVersions=[])
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_tenant(db_conn, central, update_id="u", run_timestamp="ts", progress=None)


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_firewalls")
def test_sync_tenant_alert_detail_return_state(mock_gfw, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn):
    central = MagicMock()
    central.whoami = SimpleNamespace(id="t1", data_region_url=lambda: "https://d/")
    mock_gfw.return_value = []
    mock_lic.return_value = []
    mock_alerts.return_value = [{"id": "a1"}]
    mock_get_alert.return_value = ReturnState(success=False, message="e")
    mock_fw_up.return_value = SimpleNamespace(success=True, firewalls=[], firmwareVersions=[])
    with patch("central.sync_to_db.get_new_alert_ids", return_value=["a1"]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_tenant(db_conn, central, update_id="u", run_timestamp="ts", progress=None)


@patch("central.sync_to_db.sync_tenant")
@patch("central.sync_to_db.sync_partner")
@patch("central.sync_to_db.uuid.uuid4")
def test_sync_client_credentials_partner(mock_uuid, mock_sp, mock_st, db_conn):
    mock_uuid.return_value = SimpleNamespace(hex="a" * 32)
    central = MagicMock()
    central.authenticate.return_value = SimpleNamespace(success=True)
    central.whoami = SimpleNamespace(idType="partner", id="p")
    with patch("central.sync_to_db.CentralSession", return_value=central):
        r = sync_client_credentials_to_database(
            db_conn, "id", "sec", quiet=True, progress=None
        )
    assert isinstance(r, CredentialsSyncResult)
    central.whoami = SimpleNamespace(idType="tenant", id="t")
    with patch("central.sync_to_db.CentralSession", return_value=central):
        sync_client_credentials_to_database(
            db_conn, "id", "sec", quiet=True, progress=None
        )


@patch("central.sync_to_db.CentralSession")
def test_sync_client_credentials_auth_fail(mock_cs, db_conn):
    mock_cs.return_value.authenticate.return_value = SimpleNamespace(
        success=False, message="bad"
    )
    with pytest.raises(CentralSyncAuthError):
        sync_client_credentials_to_database(db_conn, "a", "b", quiet=True)


def test_parse_args():
    with patch.object(sys, "argv", ["prog", "--db", "x.db"]):
        a = parse_args()
        assert a.db == Path("x.db")


@patch("central.sync_to_db.sync_client_credentials_to_database")
@patch("central.sync_to_db.get_connection")
@patch("central.sync_to_db.init_schema")
@patch("central.sync_to_db.configure_logging")
@patch("central.sync_to_db._cred_sources_from_args")
def test_main_happy_path(mock_cs, mock_cfg, mock_init, mock_conn, mock_sync, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    dbf = tmp_path / "d.db"
    mock_conn.return_value = MagicMock()
    mock_cs.return_value = [("a", "b")]
    mock_sync.return_value = CredentialsSyncResult(
        "sid",
        {k: {"added": 0, "updated": 0} for k in (
            "tenants", "firewalls", "licenses", "license_subscriptions",
            "alerts", "alert_details", "firmware_upgrades", "firmware_versions",
        )},
        {k: 0.0 for k in (
            "tenants", "firewalls", "licenses", "license_subscriptions",
            "alerts", "alert_details", "firmware_upgrades", "firmware_versions",
        )},
        1.0,
    )
    with patch.object(sys, "argv", ["prog", "--db", str(dbf)]):
        from central.sync_to_db import main

        main()
    mock_conn.return_value.close.assert_called()


@patch("central.sync_to_db.logger")
def test_main_inline_creds_partial(mock_log, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch.object(sys, "argv", ["prog", "--client-id", "only"]):
        from central.sync_to_db import main

        with pytest.raises(SystemExit):
            main()


@patch("central.sync_to_db.logger")
@patch("central.sync_to_db._cred_sources_from_args", side_effect=ValueError("ve"))
def test_main_cred_error(mock_cs, mock_log, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch.object(sys, "argv", ["prog", "--db", str(tmp_path / "a.db")]):
        from central.sync_to_db import main

        with pytest.raises(SystemExit):
            main()


@patch("central.sync_to_db.sync_client_credentials_to_database")
@patch("central.sync_to_db.get_connection")
@patch("central.sync_to_db.init_schema")
@patch("central.sync_to_db.configure_logging")
@patch("central.sync_to_db._cred_sources_from_args")
def test_main_auth_exit(
    mock_cred_src, mock_cfg, mock_init, mock_conn, mock_sync, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    mock_cred_src.return_value = [("a", "b")]
    mock_conn.return_value = MagicMock()
    mock_sync.side_effect = CentralSyncAuthError("auth")
    with patch.object(sys, "argv", ["prog", "--db", str(tmp_path / "b.db")]):
        from central.sync_to_db import main

        with pytest.raises(SystemExit):
            main()


@patch("central.sync_to_db.export_db_to_xlsx")
@patch("central.sync_to_db.sync_client_credentials_to_database")
@patch("central.sync_to_db.get_connection")
@patch("central.sync_to_db.init_schema")
@patch("central.sync_to_db.configure_logging")
@patch("central.sync_to_db._cred_sources_from_args")
def test_main_export_xlsx(
    mock_cred, mock_cfg, mock_init, mock_conn, mock_sync, mock_exp, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    mock_cred.return_value = [("a", "b")]
    mock_conn.return_value = MagicMock()
    mock_sync.return_value = CredentialsSyncResult(
        "s",
        {t: {"added": 0, "updated": 0} for t in (
            "tenants", "firewalls", "licenses", "license_subscriptions",
            "alerts", "alert_details", "firmware_upgrades", "firmware_versions",
        )},
        {},
        0.0,
    )
    dbf = tmp_path / "c.db"
    with patch.object(sys, "argv", ["prog", "--db", str(dbf), "-x", str(tmp_path / "out.xlsx")]):
        from central.sync_to_db import main

        main()
    mock_exp.assert_called_once()


@patch("central.sync_to_db.export_db_to_xlsx")
@patch("central.sync_to_db.sync_client_credentials_to_database")
@patch("central.sync_to_db.get_connection")
@patch("central.sync_to_db.init_schema")
@patch("central.sync_to_db.configure_logging")
@patch("central.sync_to_db._cred_sources_from_args")
def test_main_export_xlsx_default_path(
    mock_cred, mock_cfg, mock_init, mock_conn, mock_sync, mock_exp, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    mock_cred.return_value = [("a", "b")]
    mock_conn.return_value = MagicMock()
    mock_sync.return_value = CredentialsSyncResult(
        "s",
        {t: {"added": 0, "updated": 0} for t in (
            "tenants", "firewalls", "licenses", "license_subscriptions",
            "alerts", "alert_details", "firmware_upgrades", "firmware_versions",
        )},
        {},
        0.0,
    )
    dbf = tmp_path / "mydb.db"
    with patch.object(sys, "argv", ["prog", "--db", str(dbf), "-x"]):
        from central.sync_to_db import main

        main()
    mock_exp.assert_called_once()


@patch("central.sync_to_db.sync_client_credentials_to_database")
@patch("central.sync_to_db.get_connection")
@patch("central.sync_to_db.init_schema")
@patch("central.sync_to_db.configure_logging")
@patch("central.sync_to_db._cred_sources_from_args")
def test_main_multi_sources_print(
    mock_cred, mock_cfg, mock_init, mock_conn, mock_sync, tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)
    mock_cred.return_value = [("a", "b"), ("c", "d")]
    mock_conn.return_value = MagicMock()
    mock_sync.return_value = CredentialsSyncResult(
        "s",
        {t: {"added": 1, "updated": 0} for t in (
            "tenants", "firewalls", "licenses", "license_subscriptions",
            "alerts", "alert_details", "firmware_upgrades", "firmware_versions",
        )},
        {t: 0.01 for t in (
            "tenants", "firewalls", "licenses", "license_subscriptions",
            "alerts", "alert_details", "firmware_upgrades", "firmware_versions",
        )},
        0.1,
    )
    with patch.object(sys, "argv", ["prog", "--db", str(tmp_path / "m.db")]):
        from central.sync_to_db import main

        main()
    assert "creds" in capsys.readouterr().out


@patch("central.sync_to_db.sync_client_credentials_to_database")
@patch("central.sync_to_db.get_connection")
@patch("central.sync_to_db.init_schema")
@patch("central.sync_to_db.configure_logging")
def test_main_default_creds(mock_cfg, mock_init, mock_conn, mock_sync, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    mock_conn.return_value = MagicMock()
    mock_sync.return_value = CredentialsSyncResult(
        "s",
        {t: {"added": 0, "updated": 0} for t in (
            "tenants", "firewalls", "licenses", "license_subscriptions",
            "alerts", "alert_details", "firmware_upgrades", "firmware_versions",
        )},
        {},
        0.0,
    )
    with patch.object(sys, "argv", ["prog", "--db", str(tmp_path / "z.db")]):
        from central import sync_to_db as st

        with patch.object(st, "_cred_sources_from_args") as m:
            m.return_value = [("a", "b")]
            st.main()
    mock_sync.assert_called()


def test_get_creds_sync_module(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "credentials.env").write_text(
        "CENTRAL-CLIENT-ID=a\nCENTRAL-CLIENT-SECRET=b\n", encoding="utf-8"
    )
    assert get_creds()["CENTRAL-CLIENT-ID"] == "a"


def test_get_creds_sync_no_file_raises(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="No credentials"):
        get_creds()


def test_get_creds_sync_invalid_creds(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("FOO=1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="No credentials"):
        get_creds()


def test_sync_quiet_false_with_progress(db_conn):
    central = MagicMock()
    central.authenticate.return_value = SimpleNamespace(success=True)
    central.whoami = SimpleNamespace(idType="tenant", id="t")
    with patch("central.sync_to_db.CentralSession", return_value=central):
        with patch("central.sync_to_db.sync_tenant"):
            sync_client_credentials_to_database(
                db_conn, "a", "b", quiet=False, progress=SyncProgress()
            )
