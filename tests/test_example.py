"""Tests for example.py."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import example
from central.classes import WhoamiResponse
from central.firewalls.licenses.classes import License, Licenses


class _SuccessList(list):
    success = True


class _FailFirewalls:
    success = False
    message = "e"

    def __iter__(self):
        return iter([])


def test_print_group_summary(capsys):
    g = SimpleNamespace(name="G", firewalls=SimpleNamespace(total=2), parentGroup="P")
    example.print_group_summary([g])
    assert "G" in capsys.readouterr().out


def test_print_firewall_summary_empty():
    example.print_firewall_summary([])


def test_print_firewall_summary_counts(capsys):
    fw = SimpleNamespace(
        status=SimpleNamespace(
            managingStatus="approved",
            reportingStatus="approved",
            connected=True,
            suspended=True,
        )
    )
    example.print_firewall_summary([fw])
    assert "Firewall counts" in capsys.readouterr().out


def test_print_firewall_summary_pending(capsys):
    fw = SimpleNamespace(
        status=SimpleNamespace(
            managingStatus="pending",
            reportingStatus="pending",
            connected=False,
            suspended=False,
        )
    )
    example.print_firewall_summary([fw])
    assert "Pending" in capsys.readouterr().out or "Firewall counts" in capsys.readouterr().out


def test_print_firewall_summary_pending_reporting_only(capsys):
    """Cover branch 77->82: pending in reportingStatus but not in managingStatus."""
    fw = SimpleNamespace(
        status=SimpleNamespace(
            managingStatus="approved",
            reportingStatus="pending",
            connected=False,
            suspended=False,
        )
    )
    example.print_firewall_summary([fw])
    out = capsys.readouterr().out
    assert "Pending" in out


def test_print_license_summary(capsys):
    sub = SimpleNamespace(
        type="term",
        licenseIdentifier="L",
        product="P",
        startDate="s",
        endDate="e",
        perpetual=False,
        quantity=1,
        unlimited=False,
        usage=None,
    )
    lic = SimpleNamespace(serialNumber="SN", model="m", licenses=[sub])
    example.print_license_summary([lic])
    assert "SN" in capsys.readouterr().out


def test_get_creds_credentials_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "credentials.env").write_text(
        "CENTRAL-CLIENT-ID=id\nCENTRAL-CLIENT-SECRET=sec\n", encoding="utf-8"
    )
    c = example.get_creds()
    assert c["CENTRAL-CLIENT-ID"] == "id"


def test_get_creds_dotenv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "CENTRAL-CLIENT-ID=i\nCENTRAL-CLIENT-SECRET=s\n", encoding="utf-8"
    )
    c = example.get_creds()
    assert c["CENTRAL-CLIENT-ID"] == "i"


def test_get_creds_missing_raises(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(Exception, match="No credentials"):
        example.get_creds()


def test_parse_args():
    with patch.object(sys, "argv", ["ex", "-l", "DEBUG"]):
        a = example.parse_args()
        assert a.log_level == "DEBUG"


@patch("example.firmware_upgrade_check")
@patch("example.get_licenses")
@patch("example.get_firewall_groups")
@patch("example.get_firewalls")
@patch("example.configure_logging")
@patch("example.CentralSession")
@patch("example.get_creds")
def test_main_auth_fails(
    mock_creds, mock_sess, mock_cfg, mock_gfw, mock_grp, mock_lic, mock_fw
):
    mock_creds.return_value = {"CENTRAL-CLIENT-ID": "a", "CENTRAL-CLIENT-SECRET": "b"}
    mock_sess.return_value.authenticate.return_value = SimpleNamespace(
        success=False, message="bad"
    )
    with patch.object(sys, "argv", ["ex"]):
        example.main()


@patch("example.firmware_upgrade_check")
@patch("example.get_licenses")
@patch("example.get_firewall_groups")
@patch("example.get_firewalls")
@patch("example.configure_logging")
@patch("example.CentralSession")
@patch("example.get_creds")
def test_main_tenant_branch(
    mock_creds, mock_sess, mock_cfg, mock_gfw, mock_grp, mock_lic, mock_fw_chk, capsys
):
    mock_creds.return_value = {"CENTRAL-CLIENT-ID": "a", "CENTRAL-CLIENT-SECRET": "b"}
    who = WhoamiResponse(
        id="t1",
        idType="tenant",
        apiHosts={"global": "https://g/", "dataRegion": "https://h/"},
    )
    mock_sess.return_value.authenticate.return_value = SimpleNamespace(success=True)
    mock_sess.return_value.whoami = who
    fw = SimpleNamespace(
        id="f1",
        serialNumber="S",
        firmwareVersion="v",
        status=SimpleNamespace(
            managingStatus="approved",
            reportingStatus="approved",
            connected=False,
            suspended=False,
        ),
    )
    mock_gfw.return_value = [fw]
    mock_grp.return_value = []
    sub = SimpleNamespace(
        type="t",
        licenseIdentifier="l",
        product=None,
        startDate="s",
        endDate=None,
        perpetual=True,
        quantity=1,
        unlimited=False,
        usage=None,
    )
    lic = License(
        serialNumber="x",
        owner={"id": "o", "type": "partner"},
        partner={"id": "p"},
        tenant={"id": "t"},
        billingTenant=None,
        model="m",
        modelType="hardware",
        licenses=[
            {
                "id": "s",
                "licenseIdentifier": "l",
                "product": None,
                "startDate": "s",
                "perpetual": True,
                "type": "perpetual",
                "quantity": 1,
                "usage": None,
            }
        ],
    )
    mock_lic.return_value = Licenses([lic])
    info = SimpleNamespace(
        success=True,
        list_available_upgrades=lambda: [
            SimpleNamespace(serialNumber="S", firmwareVersion="v", upgradeToVersion="u")
        ],
        firewalls=[
            SimpleNamespace(serialNumber="S", firmwareVersion="v", upgradeToVersion="u")
        ],
    )
    mock_fw_chk.return_value = info
    with patch.object(sys, "argv", ["ex"]):
        example.main()
    out = capsys.readouterr().out
    assert "Firmware upgrades" in out or "firewall groups" in out.lower()


@patch("example.firmware_upgrade_check")
@patch("example.get_licenses")
@patch("example.get_firewalls")
@patch("example.configure_logging")
@patch("example.CentralSession")
@patch("example.get_creds")
def test_main_partner_branch(
    mock_creds, mock_sess, mock_cfg, mock_gfw, mock_lic, mock_fw_chk, capsys
):
    mock_creds.return_value = {"CENTRAL-CLIENT-ID": "a", "CENTRAL-CLIENT-SECRET": "b"}
    mock_sess.return_value.authenticate.return_value = SimpleNamespace(success=True)
    mock_sess.return_value.whoami = WhoamiResponse(
        id="p1", idType="partner", apiHosts={"global": "https://g/"}
    )
    tenant = SimpleNamespace(
        id="t1", name="T", dataRegion="r", billingType="b", apiHost="https://api/"
    )
    mock_sess.return_value.get_tenants.return_value = [tenant]
    mock_gfw.return_value = _FailFirewalls()
    mock_lic.side_effect = [
        Licenses([]),
        SimpleNamespace(success=False, message="e"),
    ]
    mock_fw_chk.return_value = SimpleNamespace(success=False, message="e")
    with patch.object(sys, "argv", ["ex"]):
        example.main()
    assert "t1" in capsys.readouterr().out or "Partner" in capsys.readouterr().out


@patch("example.firmware_upgrade_check")
@patch("example.get_licenses")
@patch("example.get_firewalls")
@patch("example.configure_logging")
@patch("example.CentralSession")
@patch("example.get_creds")
def test_main_partner_firmware_ok(
    mock_creds, mock_sess, mock_cfg, mock_gfw, mock_lic, mock_fw_chk, capsys
):
    mock_creds.return_value = {"CENTRAL-CLIENT-ID": "a", "CENTRAL-CLIENT-SECRET": "b"}
    mock_sess.return_value.authenticate.return_value = SimpleNamespace(success=True)
    mock_sess.return_value.whoami = WhoamiResponse(
        id="p1", idType="partner", apiHosts={"global": "https://g/"}
    )
    tenant = SimpleNamespace(
        id="t1", name="T", dataRegion="r", billingType="b", apiHost="https://api/"
    )
    mock_sess.return_value.get_tenants.return_value = [tenant]
    fw = SimpleNamespace(id="fid")
    mock_gfw.return_value = _SuccessList([fw])
    mock_lic.side_effect = [Licenses([]), Licenses([])]
    upg = SimpleNamespace(
        serialNumber="S",
        firmwareVersion="v",
        upgradeToVersion="19",
    )
    mock_fw_chk.return_value = SimpleNamespace(
        success=True,
        list_available_upgrades=lambda: [upg],
    )
    with patch.object(sys, "argv", ["ex"]):
        example.main()


@patch("example.firmware_upgrade_check")
@patch("example.get_licenses")
@patch("example.get_firewalls")
@patch("example.configure_logging")
@patch("example.CentralSession")
@patch("example.get_creds")
def test_main_partner_licenses_ok(
    mock_creds, mock_sess, mock_cfg, mock_gfw, mock_lic, mock_fw_chk
):
    mock_creds.return_value = {"CENTRAL-CLIENT-ID": "a", "CENTRAL-CLIENT-SECRET": "b"}
    mock_sess.return_value.authenticate.return_value = SimpleNamespace(success=True)
    mock_sess.return_value.whoami = WhoamiResponse(
        id="p1", idType="partner", apiHosts={"global": "https://g/"}
    )
    tenant = SimpleNamespace(
        id="t1", name="T", dataRegion="r", billingType="b", apiHost="https://api/"
    )
    mock_sess.return_value.get_tenants.return_value = [tenant]
    mock_gfw.return_value = _SuccessList([])
    lic = License(
        serialNumber="x",
        owner={"id": "o", "type": "partner"},
        partner={"id": "p"},
        tenant={"id": "t"},
        billingTenant=None,
        model="m",
        modelType="hardware",
        licenses=[],
    )
    mock_lic.side_effect = [
        Licenses([]),
        Licenses([lic]),
    ]
    mock_fw_chk.return_value = SimpleNamespace(success=False, message="x")
    with patch.object(sys, "argv", ["ex"]):
        example.main()


def test_example_test_fn(capsys):
    example.test()
    assert capsys.readouterr().out


@patch("example.firmware_upgrade_check")
@patch("example.get_licenses")
@patch("example.get_firewall_groups")
@patch("example.get_firewalls")
@patch("example.configure_logging")
@patch("example.CentralSession")
@patch("example.get_creds")
def test_main_tenant_logs_groups_and_firmware_error_message(
    mock_creds, mock_sess, mock_cfg, mock_gfw, mock_grp, mock_lic, mock_fw_chk, capsys
):
    mock_creds.return_value = {"CENTRAL-CLIENT-ID": "a", "CENTRAL-CLIENT-SECRET": "b"}
    mock_sess.return_value.authenticate.return_value = SimpleNamespace(success=True)
    mock_sess.return_value.whoami = WhoamiResponse(
        id="t1",
        idType="tenant",
        apiHosts={"global": "https://g/", "dataRegion": "https://d/"},
    )
    fw = SimpleNamespace(
        id="fid",
        status=SimpleNamespace(
            managingStatus="approved",
            reportingStatus="approved",
            connected=False,
            suspended=False,
        ),
    )
    mock_gfw.return_value = _SuccessList([fw])
    mock_grp.return_value = [SimpleNamespace(name="GrpName", id="g1")]
    mock_lic.return_value = Licenses([])
    mock_fw_chk.return_value = SimpleNamespace(success=False, message="firmware_err")
    with patch.object(sys, "argv", ["ex"]):
        example.main()
    assert "firmware_err" in capsys.readouterr().out
