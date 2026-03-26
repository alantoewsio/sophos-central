"""Tests for central.sync_to_db."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from central.classes import ReturnState
from central.firewalls.groups.classes import FirewallID, FirewallSyncStatus
from central.sync_to_db import (
    CentralSyncAuthError,
    CredentialsSyncResult,
    SyncProgress,
    _cred_sources_from_args,
    _format_duration,
    _progress_erase_prefix,
    _quiet_sync_cli_loggers,
    _sync_mdr_threat_feed_for_firewall,
    _sync_tenant_firewalls_alerts_and_details,
    _try_enable_windows_console_vt,
    ensure_tenant_record,
    export_db_to_xlsx,
    get_creds,
    get_creds_from_env_file,
    parse_args,
    sync_client_credentials_to_database,
    sync_client_credentials_to_database_incremental,
    sync_partner,
    sync_partner_incremental,
    sync_tenant,
    sync_tenant_incremental,
)

_SUMMARY_TABLE_KEYS = (
    "tenants",
    "firewalls",
    "licenses",
    "license_subscriptions",
    "alerts",
    "alert_details",
    "firmware_upgrades",
    "firmware_versions",
    "firewall_groups",
    "firewall_group_sync_status",
    "mdr_threat_feed_sync",
    "tenant_roles",
    "tenant_admins",
)


def test_format_duration():
    assert "ms" in _format_duration(0.5)
    assert "s" in _format_duration(2.0)


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


def test_try_enable_windows_console_vt_does_not_raise():
    _try_enable_windows_console_vt()


def test_progress_erase_prefix_respects_no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert _progress_erase_prefix() == "\r"
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")
    assert _progress_erase_prefix() == "\r"


def test_progress_erase_prefix_ansi_sequence_when_allowed(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    assert _progress_erase_prefix() == "\r\x1b[2K"


def test_try_enable_windows_console_vt_non_win32():
    with patch("central.sync_to_db.sys.platform", "linux"):
        _try_enable_windows_console_vt()


def _patch_win32_console_mocks(mock_k: MagicMock):
    """ctypes.windll is absent on non-Windows; inject a fake windll for tests."""
    mock_windll = MagicMock(kernel32=mock_k)
    return patch("ctypes.windll", mock_windll, create=True)


def test_try_enable_windows_console_vt_sets_mode():
    mock_k = MagicMock()
    mock_k.GetStdHandle.return_value = 1
    mock_k.GetConsoleMode.return_value = 1
    mock_k.SetConsoleMode.return_value = 1
    with patch("central.sync_to_db.sys.platform", "win32"), patch(
        "central.sync_to_db.sys.stdout.isatty", return_value=True
    ), _patch_win32_console_mocks(mock_k):
        _try_enable_windows_console_vt()
    mock_k.SetConsoleMode.assert_called_once()
    _handle, new_mode = mock_k.SetConsoleMode.call_args[0]
    assert new_mode & 0x0004


def test_try_enable_windows_console_vt_skips_if_already_on():
    mock_k = MagicMock()
    mock_k.GetStdHandle.return_value = 1

    def gcm(h, ref):
        ref._obj.value = 0x0004
        return 1

    mock_k.GetConsoleMode.side_effect = gcm
    with patch("central.sync_to_db.sys.platform", "win32"), patch(
        "central.sync_to_db.sys.stdout.isatty", return_value=True
    ), _patch_win32_console_mocks(mock_k):
        _try_enable_windows_console_vt()
    mock_k.SetConsoleMode.assert_not_called()


def test_try_enable_windows_console_vt_skips_on_get_mode_fail():
    mock_k = MagicMock()
    mock_k.GetStdHandle.return_value = 1
    mock_k.GetConsoleMode.return_value = 0
    with patch("central.sync_to_db.sys.platform", "win32"), patch(
        "central.sync_to_db.sys.stdout.isatty", return_value=True
    ), _patch_win32_console_mocks(mock_k):
        _try_enable_windows_console_vt()
    mock_k.SetConsoleMode.assert_not_called()


def test_try_enable_windows_console_vt_swallows_kernel_errors():
    mock_k = MagicMock()
    mock_k.GetStdHandle.side_effect = OSError("no console")
    with patch("central.sync_to_db.sys.platform", "win32"), patch(
        "central.sync_to_db.sys.stdout.isatty", return_value=True
    ), _patch_win32_console_mocks(mock_k):
        _try_enable_windows_console_vt()


@patch("central.sync_to_db.shutil.get_terminal_size", side_effect=OSError)
@patch("central.sync_to_db.sys.stdout.isatty", return_value=True)
def test_sync_progress_terminal_width_oserror(mock_isatty, mock_gs, monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    sp = SyncProgress()
    sp.set_total(10)
    sp.update("step", current=2)
    sp.clear()


@patch("central.sync_to_db.shutil.get_terminal_size", return_value=SimpleNamespace(columns=14))
@patch("central.sync_to_db.sys.stdout.isatty", return_value=True)
def test_sync_progress_render_truncates_line(mock_isatty, mock_gs, monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    sp = SyncProgress()
    sp._visible = True
    sp.set_total(100)
    sp.update("x" * 200, current=1)
    sp.clear()


@patch("central.sync_to_db.sys.stdout.isatty", return_value=True)
def test_sync_progress_render_no_ansi_pads_line(mock_isatty, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    sp = SyncProgress()
    sp.set_total(5)
    sp.update("hi", current=1)
    sp.clear()


@patch("central.sync_to_db.sys.stdout.isatty", return_value=True)
def test_sync_progress_clear_uses_ansi_erase(mock_isatty, monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    sp = SyncProgress()
    sp.clear()


@patch("central.sync_to_db.shutil.get_terminal_size", return_value=SimpleNamespace(columns=8))
@patch("central.sync_to_db.sys.stdout.isatty", return_value=True)
def test_sync_progress_render_hard_caps_line_length(mock_isatty, mock_gs, monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    sp = SyncProgress()
    sp._visible = True
    sp.set_total(10)
    sp.update("msg", current=5)
    sp.clear()


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
        db_conn,
        "w1",
        name="N",
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="t",
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
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
def test_sync_partner_minimal(
    mock_gfw, mock_roles, mock_admins, mock_lic, mock_alerts, mock_get_alert, mock_fw_up,
    db_conn,
):
    mock_gfw.return_value = ReturnState(success=False, message="x")
    mock_lic.return_value = ReturnState(success=False, message="x")
    mock_alerts.return_value = ReturnState(success=False, message="x")
    mock_fw_up.return_value = ReturnState(success=False, message="x")
    central = MagicMock()
    central.whoami = SimpleNamespace(id="p1")
    central.get_tenants.return_value = ReturnState(success=False, message="no tenants")
    sync_partner(
        db_conn,
        central,
        client_id="oauth-cid",
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
            client_id="oauth-cid",
            update_id="u2",
            run_timestamp="ts",
            elapsed_by_table={},
            progress=SyncProgress(),
        )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
def test_sync_partner_with_alerts_and_details(
    mock_gfw, mock_roles, mock_admins, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn
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
            pr = SyncProgress()
            pr._visible = False
            sync_partner(
                db_conn,
                central,
                client_id="oauth-cid",
                update_id="u3",
                run_timestamp="ts",
                progress=pr,
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
def test_sync_partner_licenses_fail_alerts_fail(
    mock_gfw, mock_roles, mock_admins, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn
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
            sync_partner(db_conn, central, client_id="oauth-cid", update_id="u", run_timestamp="ts", progress=None)


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
def test_sync_partner_licenses_and_firmware_success(mock_gfw, mock_roles, mock_admins, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn):
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
                client_id="oauth-cid",
                update_id="u",
                run_timestamp="ts",
                progress=progress,
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
def test_sync_partner_with_latest_raised_from_time(mock_gfw, mock_roles, mock_admins, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn):
    central = MagicMock()
    central.whoami = SimpleNamespace(id="p1")
    tenant = SimpleNamespace(id="t1", name="T", apiHost="https://h/")
    central.get_tenants.return_value = [tenant]
    mock_gfw.return_value = []
    mock_lic.return_value = []
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(success=True, firewalls=[], firmwareVersions=[])
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value="2024-06-01T12:00:00Z"):
            sync_partner(db_conn, central, client_id="oauth-cid", update_id="u", run_timestamp="ts", progress=None)


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
def test_sync_tenant_paths(mock_gfw, mock_roles, mock_admins, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn):
    central = MagicMock()
    central.whoami = SimpleNamespace(id="t1", data_region_url=lambda: "https://d/")
    mock_gfw.return_value = ReturnState(success=False, message="e")
    mock_lic.return_value = ReturnState(success=False, message="e")
    mock_alerts.return_value = ReturnState(success=False, message="e")
    mock_fw_up.return_value = ReturnState(success=False, message="e")
    sync_tenant(db_conn, central, client_id="oauth-cid", update_id="u", run_timestamp="ts", progress=None)

    mock_gfw.return_value = []
    mock_lic.return_value = []
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(success=True, firewalls=[], firmwareVersions=[])
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_tenant(
                db_conn,
                central,
                client_id="oauth-cid",
                update_id="u2",
                run_timestamp="ts",
                progress=SyncProgress(),
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins")
@patch("central.sync_to_db.get_roles")
@patch("central.sync_to_db.get_firewalls")
def test_sync_tenant_roles_admins_api_fail(
    mock_gfw, mock_roles, mock_admins, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn
):
    central = MagicMock()
    central.whoami = SimpleNamespace(id="t1", data_region_url=lambda: "https://d/")
    mock_roles.return_value = ReturnState(success=False, message="roles err")
    mock_admins.return_value = ReturnState(success=False, message="admins err")
    mock_gfw.return_value = []
    mock_lic.return_value = ReturnState(success=False, message="e")
    mock_alerts.return_value = ReturnState(success=False, message="e")
    mock_fw_up.return_value = ReturnState(success=False, message="e")
    sync_tenant(db_conn, central, client_id="oauth-cid", update_id="u", run_timestamp="ts", progress=None)


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
def test_sync_tenant_with_latest_raised_and_alert_details(
    mock_gfw, mock_roles, mock_admins, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn
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
            pr = SyncProgress()
            pr._visible = False
            sync_tenant(
                db_conn,
                central,
                client_id="oauth-cid",
                update_id="u",
                run_timestamp="ts",
                progress=pr,
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
def test_sync_tenant_with_progress_and_firmware_success(
    mock_gfw, mock_roles, mock_admins, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn
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
                client_id="oauth-cid",
                update_id="u",
                run_timestamp="ts",
                progress=progress,
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
def test_sync_tenant_licenses_fail(mock_gfw, mock_roles, mock_admins, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn):
    central = MagicMock()
    central.whoami = SimpleNamespace(id="t1", data_region_url=lambda: "https://d/")
    mock_gfw.return_value = []
    mock_lic.return_value = ReturnState(success=False, message="lic fail")
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(success=True, firewalls=[], firmwareVersions=[])
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_tenant(db_conn, central, client_id="oauth-cid", update_id="u", run_timestamp="ts", progress=None)


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
def test_sync_tenant_alert_detail_return_state(mock_gfw, mock_roles, mock_admins, mock_lic, mock_alerts, mock_get_alert, mock_fw_up, db_conn):
    central = MagicMock()
    central.whoami = SimpleNamespace(id="t1", data_region_url=lambda: "https://d/")
    mock_gfw.return_value = []
    mock_lic.return_value = []
    mock_alerts.return_value = [{"id": "a1"}]
    mock_get_alert.return_value = ReturnState(success=False, message="e")
    mock_fw_up.return_value = SimpleNamespace(success=True, firewalls=[], firmwareVersions=[])
    with patch("central.sync_to_db.get_new_alert_ids", return_value=["a1"]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_tenant(db_conn, central, client_id="oauth-cid", update_id="u", run_timestamp="ts", progress=None)


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


@patch("central.sync_to_db.sync_tenant_incremental")
@patch("central.sync_to_db.sync_partner_incremental")
@patch("central.sync_to_db.uuid.uuid4")
def test_sync_client_credentials_incremental_routing(
    mock_uuid, mock_spi, mock_sti, db_conn
):
    mock_uuid.return_value = SimpleNamespace(hex="c" * 32)
    central = MagicMock()
    central.authenticate.return_value = SimpleNamespace(success=True)
    central.whoami = SimpleNamespace(idType="partner", id="p")
    with patch("central.sync_to_db.CentralSession", return_value=central):
        r = sync_client_credentials_to_database_incremental(
            db_conn, "id", "sec", quiet=True, progress=None
        )
    assert isinstance(r, CredentialsSyncResult)
    mock_spi.assert_called_once()
    mock_sti.assert_not_called()
    central.whoami = SimpleNamespace(idType="tenant", id="t")
    with patch("central.sync_to_db.CentralSession", return_value=central):
        sync_client_credentials_to_database_incremental(
            db_conn, "id", "sec", quiet=True, progress=None
        )
    assert mock_sti.call_count == 1


@patch("central.sync_to_db.CentralSession")
def test_sync_client_credentials_incremental_auth_fail(mock_cs, db_conn):
    mock_cs.return_value.authenticate.return_value = SimpleNamespace(
        success=False, message="bad"
    )
    with pytest.raises(CentralSyncAuthError):
        sync_client_credentials_to_database_incremental(db_conn, "a", "b", quiet=True)


@patch("central.sync_to_db.CentralSession")
def test_sync_client_credentials_incremental_quiet_false(mock_cs, db_conn):
    mock_cs.return_value.authenticate.return_value = SimpleNamespace(success=True)
    mock_cs.return_value.whoami = SimpleNamespace(idType="tenant", id="tid")
    with patch("central.sync_to_db.sync_tenant_incremental"):
        sync_client_credentials_to_database_incremental(
            db_conn, "a", "b", quiet=False, progress=None
        )


@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_firewalls")
def test_sync_partner_incremental_minimal(
    mock_gfw, mock_alerts, mock_get_alert, db_conn
):
    mock_gfw.return_value = ReturnState(success=False, message="x")
    mock_alerts.return_value = ReturnState(success=False, message="x")
    central = MagicMock()
    central.whoami = SimpleNamespace(id="p1")
    central.get_tenants.return_value = ReturnState(success=False, message="no tenants")
    sync_partner_incremental(
        db_conn,
        central,
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="ts",
        progress=None,
    )
    tenant = SimpleNamespace(id="t1", name="T", apiHost="https://h/")
    central.get_tenants.return_value = [tenant]
    mock_gfw.return_value = []
    mock_alerts.return_value = []
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]), patch(
        "central.sync_to_db.get_latest_alert_raised_at", return_value=None
    ):
        sync_partner_incremental(
            db_conn,
            central,
            client_id="oauth-cid",
            update_id="u2",
            run_timestamp="ts",
            elapsed_by_table={},
            progress=SyncProgress(),
        )


@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_firewalls")
def test_sync_partner_incremental_alert_details(
    mock_gfw, mock_alerts, mock_get_alert, db_conn
):
    central = MagicMock()
    central.whoami = SimpleNamespace(id="p1")
    tenant = SimpleNamespace(id="t1", name="T", apiHost="https://h/")
    central.get_tenants.return_value = [tenant]
    mock_gfw.return_value = []
    mock_alerts.return_value = [SimpleNamespace(id="a1")]
    mock_get_alert.return_value = {"id": "a1", "category": "c"}
    with patch("central.sync_to_db.get_new_alert_ids", return_value=["a1"]), patch(
        "central.sync_to_db.get_latest_alert_raised_at", return_value=None
    ):
        sync_partner_incremental(
            db_conn,
            central,
            client_id="oauth-cid",
            update_id="ud",
            run_timestamp="ts",
            progress=None,
        )


@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_firewalls")
def test_sync_tenant_incremental(mock_gfw, mock_alerts, mock_get_alert, db_conn):
    central = MagicMock()
    central.whoami = SimpleNamespace(
        id="t1", data_region_url=lambda: "https://h/"
    )
    mock_gfw.return_value = []
    mock_alerts.return_value = []
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]), patch(
        "central.sync_to_db.get_latest_alert_raised_at", return_value=None
    ):
        sync_tenant_incremental(
            db_conn,
            central,
            client_id="oauth-cid",
            update_id="u",
            run_timestamp="ts",
            progress=SyncProgress(),
        )


@patch("central.sync_to_db.get_firewalls", return_value=[])
@patch("central.sync_to_db.get_alerts", return_value=ReturnState(success=False, message="e"))
@patch("central.sync_to_db.get_new_alert_ids", return_value=[])
@patch(
    "central.sync_to_db.get_latest_alert_raised_at",
    return_value=None,
)
def test_sync_tenant_firewalls_alerts_and_details_branch_failures(
    mock_gfw, mock_alerts, mock_new, mock_latest, db_conn
):
    central = MagicMock()
    elapsed = {}
    _sync_tenant_firewalls_alerts_and_details(
        db_conn,
        central,
        tenant_id="t1",
        url_base="https://h/",
        tenant_display_name="TD",
        client_id="c",
        update_id="u",
        run_timestamp="ts",
        elapsed_by_table=elapsed,
        progress=None,
        progress_label_prefix="",
        progress_first_step=None,
    )
    mock_gfw.return_value = ReturnState(success=False, message="fw")
    _sync_tenant_firewalls_alerts_and_details(
        db_conn,
        central,
        tenant_id="t2",
        url_base="https://h/",
        tenant_display_name="TD",
        client_id="c",
        update_id="u",
        run_timestamp="ts",
        elapsed_by_table=elapsed,
        progress=None,
        progress_label_prefix="",
        progress_first_step=None,
    )


@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts", return_value=[])
@patch("central.sync_to_db.get_firewalls", return_value=[])
@patch("central.sync_to_db.get_new_alert_ids", return_value=[])
def test_sync_tenant_firewalls_alerts_and_details_with_progress(
    mock_new, mock_gfw, mock_alerts, mock_get_alert, db_conn
):
    central = MagicMock()
    sp = SyncProgress()
    sp._visible = False
    with patch(
        "central.sync_to_db.get_latest_alert_raised_at", return_value=None
    ):
        _sync_tenant_firewalls_alerts_and_details(
            db_conn,
            central,
            tenant_id="t1",
            url_base="https://h/",
            tenant_display_name="TD",
            client_id="c",
            update_id="u",
            run_timestamp="ts",
            elapsed_by_table={},
            progress=sp,
            progress_label_prefix="P: ",
            progress_first_step=0,
        )


def test_sync_tenant_firewalls_alerts_and_details_firewalls_api_failed(db_conn):
    central = MagicMock()
    with patch(
        "central.sync_to_db.get_firewalls",
        return_value=ReturnState(success=False, message="fwfail"),
    ), patch("central.sync_to_db.get_alerts", return_value=[]), patch(
        "central.sync_to_db.get_new_alert_ids", return_value=[]
    ), patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
        _sync_tenant_firewalls_alerts_and_details(
            db_conn,
            central,
            tenant_id="t1",
            url_base="https://h/",
            tenant_display_name="TD",
            client_id="c",
            update_id="u",
            run_timestamp="ts",
            elapsed_by_table={},
            progress=None,
            progress_label_prefix="",
            progress_first_step=None,
        )


def test_sync_tenant_firewalls_alerts_and_details_success_rows_and_details(
    db_conn,
):
    central = MagicMock()
    sp = SyncProgress()
    sp._visible = False
    with patch(
        "central.sync_to_db.get_latest_alert_raised_at",
        return_value="2024-06-01T00:00:00Z",
    ), patch(
        "central.sync_to_db.get_new_alert_ids", return_value=["a1", "a2"]
    ), patch(
        "central.sync_to_db.get_firewalls",
        return_value=[
            SimpleNamespace(
                id="fw1",
                serialNumber="sn",
                tenant=SimpleNamespace(id="t1"),
                group=None,
                status=None,
            )
        ],
    ), patch("central.sync_to_db.get_alerts", return_value=[]), patch(
        "central.sync_to_db.get_alert",
        side_effect=[
            SimpleNamespace(id="a1"),
            ReturnState(success=False, message="d2"),
        ],
    ):
        _sync_tenant_firewalls_alerts_and_details(
            db_conn,
            central,
            tenant_id="t1",
            url_base="https://h/",
            tenant_display_name="TD",
            client_id="c",
            update_id="u",
            run_timestamp="ts",
            elapsed_by_table={},
            progress=sp,
            progress_label_prefix="",
            progress_first_step=0,
        )


def test_sync_tenant_incremental_default_elapsed_and_progress(db_conn):
    central = MagicMock()
    central.whoami = SimpleNamespace(
        id="t1", data_region_url=lambda: "https://h/"
    )
    prog = MagicMock()
    with patch("central.sync_to_db._sync_tenant_firewalls_alerts_and_details"):
        sync_tenant_incremental(
            db_conn,
            central,
            client_id="oauth-cid",
            update_id="u",
            run_timestamp="ts",
            elapsed_by_table=None,
            progress=prog,
        )
    prog.set_total.assert_called_once_with(4)
    prog.update.assert_any_call("Tenant record", 0)


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
    with patch.object(sys, "argv", ["prog", "--db", "x.db", "--mdr"]):
        assert parse_args().mdr is True
    with patch.object(sys, "argv", ["prog", "--db", "x.db", "--incremental"]):
        assert parse_args().incremental is True


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
        {k: {"added": 0, "updated": 0} for k in _SUMMARY_TABLE_KEYS},
        {k: 0.0 for k in _SUMMARY_TABLE_KEYS},
        1.0,
    )
    with patch.object(sys, "argv", ["prog", "--db", str(dbf)]):
        from central.sync_to_db import main

        main()
    mock_conn.return_value.close.assert_called()


@patch("central.sync_to_db.sync_client_credentials_to_database_incremental")
@patch("central.sync_to_db.get_connection")
@patch("central.sync_to_db.init_schema")
@patch("central.sync_to_db.configure_logging")
@patch("central.sync_to_db._cred_sources_from_args")
def test_main_happy_path_incremental(
    mock_cred_src, mock_cfg, mock_init, mock_conn, mock_sync_inc, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    dbf = tmp_path / "d.db"
    mock_conn.return_value = MagicMock()
    mock_cred_src.return_value = [("a", "b")]
    mock_sync_inc.return_value = CredentialsSyncResult(
        "sid",
        {k: {"added": 0, "updated": 0} for k in _SUMMARY_TABLE_KEYS},
        {k: 0.0 for k in _SUMMARY_TABLE_KEYS},
        1.0,
    )
    with patch.object(sys, "argv", ["prog", "--db", str(dbf), "--incremental"]):
        from central.sync_to_db import main

        main()
    mock_sync_inc.assert_called_once()
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
        {t: {"added": 0, "updated": 0} for t in _SUMMARY_TABLE_KEYS},
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
        {t: {"added": 0, "updated": 0} for t in _SUMMARY_TABLE_KEYS},
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
        {t: {"added": 1, "updated": 0} for t in _SUMMARY_TABLE_KEYS},
        {t: 0.01 for t in _SUMMARY_TABLE_KEYS},
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
        {t: {"added": 0, "updated": 0} for t in _SUMMARY_TABLE_KEYS},
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


def test_sync_client_credentials_passes_sync_mdr(db_conn):
    with patch("central.sync_to_db.sync_tenant") as mock_st:
        central = MagicMock()
        central.authenticate.return_value = SimpleNamespace(success=True)
        central.whoami = SimpleNamespace(idType="tenant", id="t")
        with patch("central.sync_to_db.CentralSession", return_value=central):
            sync_client_credentials_to_database(
                db_conn, "a", "b", quiet=True, sync_mdr=True
            )
    assert mock_st.call_args[1]["sync_mdr"] is True


def test_mdr_sync_request_failed(db_conn):
    central = MagicMock()
    with patch(
        "central.sync_to_db.get_mdr_threat_feed",
        return_value=ReturnState(success=False, message="fail", value=None),
    ):
        _sync_mdr_threat_feed_for_firewall(
            db_conn,
            central,
            firewall_id="fw1",
            tenant_id="t1",
            url_base="https://h/",
            client_id="c",
            update_id="u1",
            run_timestamp="ts",
        )
    row = db_conn.execute(
        "SELECT poll_status, detail_message FROM mdr_threat_feed_sync WHERE firewall_id=?",
        ("fw1",),
    ).fetchone()
    assert row["poll_status"] == "request_failed"


def test_mdr_sync_no_transaction_id(db_conn):
    central = MagicMock()
    kick_val = MagicMock(success=True, data={})
    with patch(
        "central.sync_to_db.get_mdr_threat_feed",
        return_value=ReturnState(success=True, value=kick_val),
    ):
        _sync_mdr_threat_feed_for_firewall(
            db_conn,
            central,
            firewall_id="fw2",
            tenant_id="t1",
            url_base="https://h/",
            client_id="c",
            update_id="u1",
            run_timestamp="ts",
        )
    row = db_conn.execute(
        "SELECT poll_status FROM mdr_threat_feed_sync WHERE firewall_id=?",
        ("fw2",),
    ).fetchone()
    assert row["poll_status"] == "no_transaction_id"


def test_mdr_sync_finished_and_timeout(db_conn):
    central = MagicMock()

    def _kick():
        kv = MagicMock(success=True, data={"transactionId": "tx"})
        return ReturnState(success=True, value=kv)

    tr_done = MagicMock(success=True, data={"status": "finished", "result": "success"})
    tr_pending = MagicMock(success=True, data={"status": "pending"})

    with patch("central.sync_to_db.get_mdr_threat_feed", side_effect=[_kick()]):
        with patch(
            "central.sync_to_db.get_firewall_transaction",
            return_value=ReturnState(success=True, value=tr_done),
        ):
            _sync_mdr_threat_feed_for_firewall(
                db_conn,
                central,
                firewall_id="fw3",
                tenant_id="t1",
                url_base="https://h/",
                client_id="c",
                update_id="u1",
                run_timestamp="ts",
                max_polls=3,
                sleep_fn=lambda _s: None,
            )
    assert (
        db_conn.execute(
            "SELECT poll_status, transaction_result FROM mdr_threat_feed_sync WHERE firewall_id=?",
            ("fw3",),
        ).fetchone()["poll_status"]
        == "finished"
    )

    with patch("central.sync_to_db.get_mdr_threat_feed", side_effect=[_kick()]):
        with patch(
            "central.sync_to_db.get_firewall_transaction",
            return_value=ReturnState(success=True, value=tr_pending),
        ):
            _sync_mdr_threat_feed_for_firewall(
                db_conn,
                central,
                firewall_id="fw4",
                tenant_id="t1",
                url_base="https://h/",
                client_id="c",
                update_id="u1",
                run_timestamp="ts",
                max_polls=2,
                sleep_fn=lambda _s: None,
            )
    assert (
        db_conn.execute(
            "SELECT poll_status FROM mdr_threat_feed_sync WHERE firewall_id=?",
            ("fw4",),
        ).fetchone()["poll_status"]
        == "timeout"
    )


def test_mdr_sync_poll_return_state_fails(db_conn):
    central = MagicMock()
    kick_val = MagicMock(success=True, data={"transactionId": "tx"})
    with patch(
        "central.sync_to_db.get_mdr_threat_feed",
        return_value=ReturnState(success=True, value=kick_val),
    ):
        with patch(
            "central.sync_to_db.get_firewall_transaction",
            return_value=ReturnState(success=False, message="tx bad", value=None),
        ):
            _sync_mdr_threat_feed_for_firewall(
                db_conn,
                central,
                firewall_id="fw5",
                tenant_id="t1",
                url_base="https://h/",
                client_id="c",
                update_id="u1",
                run_timestamp="ts",
            )
    assert (
        db_conn.execute(
            "SELECT poll_status FROM mdr_threat_feed_sync WHERE firewall_id=?",
            ("fw5",),
        ).fetchone()["poll_status"]
        == "poll_failed"
    )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
@patch("central.sync_to_db.get_firewall_group_sync_status")
@patch("central.sync_to_db.get_firewall_groups")
def test_sync_partner_groups_sync_status_and_mdr(
    mock_grp,
    mock_gss,
    mock_gfw,
    mock_roles,
    mock_admins,
    mock_lic,
    mock_alerts,
    mock_get_alert,
    mock_fw_up,
    db_conn,
):
    grp = SimpleNamespace(id="g1", name="G1")
    mock_grp.return_value = [grp]
    mock_gss.return_value = [
        FirewallSyncStatus(
            firewall=FirewallID(id="fw1"),
            status="inSync",
            lastUpdatedAt="2020-01-01T00:00:00Z",
        )
    ]
    central = MagicMock()
    central.whoami = SimpleNamespace(id="p1")
    tenant = SimpleNamespace(id="t1", name="T", apiHost="https://h/")
    central.get_tenants.return_value = [tenant]
    fw_obj = SimpleNamespace(
        id="fw1",
        serialNumber="S",
        tenant=SimpleNamespace(id="t1"),
        group=None,
        status=None,
    )
    mock_gfw.return_value = [fw_obj]
    mock_lic.return_value = []
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(
        success=True, firewalls=[], firmwareVersions=[]
    )
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            with patch(
                "central.sync_to_db._sync_mdr_threat_feed_for_firewall"
            ) as mock_mdr:
                sync_partner(
                    db_conn,
                    central,
                    client_id="oauth-cid",
                    update_id="ug",
                    run_timestamp="ts",
                    progress=None,
                    sync_mdr=True,
                )
                mock_mdr.assert_called_once()
    n_g = db_conn.execute(
        "SELECT COUNT(*) FROM firewall_groups WHERE id=?", ("g1",)
    ).fetchone()[0]
    n_s = db_conn.execute(
        "SELECT COUNT(*) FROM firewall_group_sync_status WHERE group_id=? AND firewall_id=?",
        ("g1", "fw1"),
    ).fetchone()[0]
    assert n_g == 1 and n_s == 1
    raw = db_conn.execute(
        "SELECT firewalls_items_json FROM firewall_groups WHERE id=?",
        ("g1",),
    ).fetchone()[0]
    assert json.loads(raw) == [{"id": "fw1"}]


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
@patch("central.sync_to_db.get_firewall_group_sync_status")
@patch("central.sync_to_db.get_firewall_groups")
def test_sync_partner_groups_api_failures(
    mock_grp,
    mock_gss,
    mock_gfw,
    mock_roles,
    mock_admins,
    mock_lic,
    mock_alerts,
    mock_get_alert,
    mock_fw_up,
    db_conn,
):
    mock_grp.return_value = ReturnState(success=False, message="nogroups")
    mock_gss.return_value = []
    central = MagicMock()
    central.whoami = SimpleNamespace(id="p1")
    tenant = SimpleNamespace(id="t1", name="T", apiHost="https://h/")
    central.get_tenants.return_value = [tenant]
    mock_gfw.return_value = []
    mock_lic.return_value = []
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(
        success=True, firewalls=[], firmwareVersions=[]
    )
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_partner(
                db_conn,
                central,
                client_id="oauth-cid",
                update_id="uf",
                run_timestamp="ts",
                progress=None,
            )
    mock_grp.return_value = [SimpleNamespace(id="g2")]
    mock_gss.return_value = ReturnState(success=False, message="nosync")
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_partner(
                db_conn,
                central,
                client_id="oauth-cid",
                update_id="uf2",
                run_timestamp="ts",
                progress=None,
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
@patch("central.sync_to_db.get_firewall_group_sync_status")
@patch("central.sync_to_db.get_firewall_groups")
def test_sync_partner_firewall_api_failure_warns(
    mock_grp,
    mock_gss,
    mock_gfw,
    mock_roles,
    mock_admins,
    mock_lic,
    mock_alerts,
    mock_get_alert,
    mock_fw_up,
    db_conn,
):
    mock_gfw.return_value = ReturnState(success=False, message="no fw")
    mock_grp.return_value = []
    mock_gss.return_value = []
    central = MagicMock()
    central.whoami = SimpleNamespace(id="p1")
    tenant = SimpleNamespace(id="t1", name="T", apiHost="https://h/")
    central.get_tenants.return_value = [tenant]
    mock_lic.return_value = []
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(
        success=True, firewalls=[], firmwareVersions=[]
    )
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_partner(
                db_conn,
                central,
                client_id="oauth-cid",
                update_id="ufw",
                run_timestamp="ts",
                progress=None,
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
@patch("central.sync_to_db.get_firewall_group_sync_status")
@patch("central.sync_to_db.get_firewall_groups")
def test_sync_partner_firmware_upgrade_check_fails(
    mock_grp,
    mock_gss,
    mock_gfw,
    mock_roles,
    mock_admins,
    mock_lic,
    mock_alerts,
    mock_get_alert,
    mock_fw_up,
    db_conn,
):
    fw_obj = SimpleNamespace(
        id="fw1",
        serialNumber="S",
        tenant=SimpleNamespace(id="t1"),
        group=None,
        status=None,
    )
    mock_gfw.return_value = [fw_obj]
    mock_grp.return_value = []
    mock_gss.return_value = []
    central = MagicMock()
    central.whoami = SimpleNamespace(id="p1")
    tenant = SimpleNamespace(id="t1", name="T", apiHost="https://h/")
    central.get_tenants.return_value = [tenant]
    mock_lic.return_value = []
    mock_alerts.return_value = []
    mock_fw_up.return_value = ReturnState(success=False, message="fwup")
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_partner(
                db_conn,
                central,
                client_id="oauth-cid",
                update_id="uff",
                run_timestamp="ts",
                progress=None,
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
@patch("central.sync_to_db.get_firewall_group_sync_status")
@patch("central.sync_to_db.get_firewall_groups")
def test_sync_partner_mdr_with_progress_updates(
    mock_grp,
    mock_gss,
    mock_gfw,
    mock_roles,
    mock_admins,
    mock_lic,
    mock_alerts,
    mock_get_alert,
    mock_fw_up,
    db_conn,
):
    mock_grp.return_value = []
    mock_gss.return_value = []
    central = MagicMock()
    central.whoami = SimpleNamespace(id="p1")
    tenant = SimpleNamespace(id="t1", name="T", apiHost="https://h/")
    central.get_tenants.return_value = [tenant]
    fw_obj = SimpleNamespace(
        id="fw1",
        serialNumber="S",
        tenant=SimpleNamespace(id="t1"),
        group=None,
        status=None,
    )
    mock_gfw.return_value = [fw_obj]
    mock_lic.return_value = []
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(
        success=True, firewalls=[], firmwareVersions=[]
    )
    pr = SyncProgress()
    pr._visible = False
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            with patch("central.sync_to_db._sync_mdr_threat_feed_for_firewall"):
                sync_partner(
                    db_conn,
                    central,
                    client_id="oauth-cid",
                    update_id="umdr",
                    run_timestamp="ts",
                    progress=pr,
                    sync_mdr=True,
                )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
@patch("central.sync_to_db.get_firewall_group_sync_status")
@patch("central.sync_to_db.get_firewall_groups")
def test_sync_partner_alert_detail_skips_return_state(
    mock_grp,
    mock_gss,
    mock_gfw,
    mock_roles,
    mock_admins,
    mock_lic,
    mock_alerts,
    mock_get_alert,
    mock_fw_up,
    db_conn,
):
    mock_grp.return_value = []
    mock_gss.return_value = []
    central = MagicMock()
    central.whoami = SimpleNamespace(id="p1")
    tenant = SimpleNamespace(id="t1", name="T", apiHost="https://h/")
    central.get_tenants.return_value = [tenant]
    mock_gfw.return_value = []
    mock_lic.return_value = []
    mock_alerts.return_value = [SimpleNamespace(id="a1")]
    mock_get_alert.return_value = ReturnState(success=False, message="d")
    mock_fw_up.return_value = SimpleNamespace(
        success=True, firewalls=[], firmwareVersions=[]
    )
    with patch("central.sync_to_db.get_new_alert_ids", return_value=["a1"]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_partner(
                db_conn,
                central,
                client_id="oauth-cid",
                update_id="uad",
                run_timestamp="ts",
                progress=None,
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
@patch("central.sync_to_db.get_firewall_group_sync_status")
@patch("central.sync_to_db.get_firewall_groups")
def test_sync_tenant_firewall_groups_api_fail(
    mock_grp,
    mock_gss,
    mock_gfw,
    mock_roles,
    mock_admins,
    mock_lic,
    mock_alerts,
    mock_get_alert,
    mock_fw_up,
    db_conn,
):
    central = MagicMock()
    central.whoami = SimpleNamespace(id="t1", data_region_url=lambda: "https://d/")
    mock_gfw.return_value = []
    mock_lic.return_value = []
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(
        success=True, firewalls=[], firmwareVersions=[]
    )
    mock_grp.return_value = ReturnState(success=False, message="gf")
    mock_gss.return_value = []
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_tenant(
                db_conn,
                central,
                client_id="oauth-cid",
                update_id="utg",
                run_timestamp="ts",
                progress=None,
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
@patch("central.sync_to_db.get_firewall_group_sync_status")
@patch("central.sync_to_db.get_firewall_groups")
def test_sync_tenant_groups_sync_mdr_and_firmware_fail(
    mock_grp,
    mock_gss,
    mock_gfw,
    mock_roles,
    mock_admins,
    mock_lic,
    mock_alerts,
    mock_get_alert,
    mock_fw_up,
    db_conn,
):
    central = MagicMock()
    central.whoami = SimpleNamespace(id="t1", data_region_url=lambda: "https://d/")
    mock_gfw.return_value = [
        SimpleNamespace(
            id="f1",
            serialNumber="SN",
            tenant=SimpleNamespace(id="t1"),
            group=None,
            status=None,
        )
    ]
    mock_lic.return_value = []
    mock_alerts.return_value = []
    mock_fw_up.return_value = ReturnState(success=False, message="badfw")
    g = SimpleNamespace(id="tg1", name="G")
    mock_grp.return_value = [g]
    mock_gss.return_value = [
        FirewallSyncStatus(
            firewall=FirewallID(id="f1"),
            status="syncing",
            lastUpdatedAt="2021-01-01",
        )
    ]
    pr = SyncProgress()
    pr._visible = False
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            with patch("central.sync_to_db._sync_mdr_threat_feed_for_firewall"):
                sync_tenant(
                    db_conn,
                    central,
                    client_id="oauth-cid",
                    update_id="utm",
                    run_timestamp="ts",
                    progress=pr,
                    sync_mdr=True,
                )


@patch("central.sync_to_db.shutil.get_terminal_size", return_value=SimpleNamespace(columns=25))
@patch("central.sync_to_db.sys.stdout.isatty", return_value=True)
def test_sync_progress_no_color_ljusts_line(mock_isatty, mock_gs, monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    sp = SyncProgress()
    sp._visible = True
    sp.set_total(3)
    sp.update("short", current=1)
    sp.clear()


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
@patch("central.sync_to_db.get_firewall_group_sync_status")
@patch("central.sync_to_db.get_firewall_groups")
def test_sync_partner_group_sync_status_call_fails(
    mock_grp,
    mock_gss,
    mock_gfw,
    mock_roles,
    mock_admins,
    mock_lic,
    mock_alerts,
    mock_get_alert,
    mock_fw_up,
    db_conn,
):
    mock_grp.return_value = [SimpleNamespace(id="gx")]
    mock_gss.return_value = ReturnState(success=False, message="syncfail")
    central = MagicMock()
    central.whoami = SimpleNamespace(id="p1")
    tenant = SimpleNamespace(id="t1", name="T", apiHost="https://h/")
    central.get_tenants.return_value = [tenant]
    mock_gfw.return_value = []
    mock_lic.return_value = []
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(
        success=True, firewalls=[], firmwareVersions=[]
    )
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_partner(
                db_conn,
                central,
                client_id="oauth-cid",
                update_id="ugs",
                run_timestamp="ts",
                progress=None,
            )


@patch("central.sync_to_db.firmware_upgrade_check")
@patch("central.sync_to_db.get_alert")
@patch("central.sync_to_db.get_alerts")
@patch("central.sync_to_db.get_licenses")
@patch("central.sync_to_db.get_admins", return_value=[])
@patch("central.sync_to_db.get_roles", return_value=[])
@patch("central.sync_to_db.get_firewalls")
@patch("central.sync_to_db.get_firewall_group_sync_status")
@patch("central.sync_to_db.get_firewall_groups")
def test_sync_tenant_group_sync_status_call_fails(
    mock_grp,
    mock_gss,
    mock_gfw,
    mock_roles,
    mock_admins,
    mock_lic,
    mock_alerts,
    mock_get_alert,
    mock_fw_up,
    db_conn,
):
    central = MagicMock()
    central.whoami = SimpleNamespace(id="t1", data_region_url=lambda: "https://d/")
    mock_gfw.return_value = []
    mock_lic.return_value = []
    mock_alerts.return_value = []
    mock_fw_up.return_value = SimpleNamespace(
        success=True, firewalls=[], firmwareVersions=[]
    )
    mock_grp.return_value = [SimpleNamespace(id="gy")]
    mock_gss.return_value = ReturnState(success=False, message="nope")
    with patch("central.sync_to_db.get_new_alert_ids", return_value=[]):
        with patch("central.sync_to_db.get_latest_alert_raised_at", return_value=None):
            sync_tenant(
                db_conn,
                central,
                client_id="oauth-cid",
                update_id="utgs",
                run_timestamp="ts",
                progress=None,
            )


@patch("central.sync_to_db.sync_client_credentials_to_database")
@patch("central.sync_to_db.get_connection")
@patch("central.sync_to_db.init_schema")
@patch("central.sync_to_db.configure_logging")
@patch("central.sync_to_db._cred_sources_from_args")
def test_main_passes_mdr_flag_to_sync(
    mock_cred, mock_cfg, mock_init, mock_conn, mock_sync, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    mock_cred.return_value = [("a", "b")]
    mock_conn.return_value = MagicMock()
    mock_sync.return_value = CredentialsSyncResult(
        "s",
        {t: {"added": 0, "updated": 0} for t in _SUMMARY_TABLE_KEYS},
        {},
        0.0,
    )
    dbf = tmp_path / "mdr.db"
    with patch.object(sys, "argv", ["prog", "--db", str(dbf), "--mdr"]):
        from central.sync_to_db import main

        main()
    assert mock_sync.call_args[1]["sync_mdr"] is True
