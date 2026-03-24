"""Tests for central.firewalls.mdr.methods."""

from unittest.mock import MagicMock

from central.classes import CentralResponse, ReturnState
from central.firewalls.mdr.methods import (
    delete_all_mdr_threat_feed_indicators,
    delete_mdr_threat_feed_indicators,
    get_firewall_transaction,
    get_mdr_threat_feed,
    patch_mdr_threat_feed_settings,
    search_mdr_threat_feed_indicators,
    create_mdr_threat_feed_indicators,
)


def _cr(code: int, data: dict | None = None):
    return CentralResponse(
        MagicMock(status_code=code, json=lambda: data if data is not None else {})
    )


def _rs(cr: CentralResponse):
    return ReturnState(success=cr.success, value=cr)


def test_get_mdr_threat_feed_uses_get_page():
    central = MagicMock()
    central.get_page.return_value = _rs(_cr(202, {"transactionId": "t1"}))
    out = get_mdr_threat_feed(central, "fw1")
    assert out.success
    assert out.value.data["transactionId"] == "t1"
    central.get_page.assert_called_once()
    path = central.get_page.call_args[0][0]
    assert path.endswith("/mdr-threat-feed")


def test_patch_mdr_settings_requires_field():
    out = patch_mdr_threat_feed_settings(MagicMock(), "fw1")
    assert out.success is False


def test_patch_mdr_settings_success():
    central = MagicMock()
    central.patch.return_value = _rs(_cr(202, {"transactionId": "x"}))
    out = patch_mdr_threat_feed_settings(central, "fw1", enabled=True)
    assert out.success
    assert "settings" in central.patch.call_args[0][0]


def test_create_delete_search_indicators_paths():
    central = MagicMock()
    central.post.return_value = _rs(_cr(202, {"transactionId": "a"}))
    create_mdr_threat_feed_indicators(
        central, "fw", [{"value": "1.1.1.1", "type": "ipv4-addr"}]
    )
    p0 = central.post.call_args_list[0][0][0]
    assert p0.endswith("/mdr-threat-feed/indicators")

    central.post.return_value = _rs(_cr(202, {"transactionId": "b"}))
    delete_mdr_threat_feed_indicators(
        central, "fw", [{"value": "1.1.1.1", "type": "ipv4-addr"}]
    )
    p1 = central.post.call_args_list[1][0][0]
    assert "/indicators/delete" in p1

    central.post.return_value = _rs(_cr(202, {"transactionId": "c"}))
    search_mdr_threat_feed_indicators(central, "fw", ["1.1.1.1"])
    p2 = central.post.call_args_list[2][0][0]
    assert "/indicators/search" in p2


def test_delete_all_indicators():
    central = MagicMock()
    central.delete.return_value = _rs(_cr(202, {"transactionId": "d"}))
    out = delete_all_mdr_threat_feed_indicators(central, "fw")
    assert out.success
    assert central.delete.call_args[0][0].endswith("/mdr-threat-feed/indicators")


def test_get_firewall_transaction_fields_param():
    central = MagicMock()
    central.get_page.return_value = _rs(_cr(200, {"id": "tx", "status": "finished"}))
    out = get_firewall_transaction(
        central, "fw", "tx1", fields=["request", "response"]
    )
    assert out.success
    _, kwargs = central.get_page.call_args
    assert kwargs["params"] == {"fields": "request,response"}


def test_mdr_no_value_returns_error():
    central = MagicMock()
    central.get_page.return_value = ReturnState(
        success=False, message="Error: not authenticated", value=None
    )
    out = get_mdr_threat_feed(central, "fw")
    assert out.success is False
    assert "not authenticated" in (out.message or "")


def test_mdr_http_error_response():
    central = MagicMock()
    central.get_page.return_value = _rs(_cr(403, {"error": "denied"}))
    out = get_mdr_threat_feed(central, "fw")
    assert out.success is False


def test_patch_mdr_action_only():
    central = MagicMock()
    central.patch.return_value = _rs(_cr(202, {"transactionId": "t"}))
    patch_mdr_threat_feed_settings(central, "fw", action="logOnly")
    assert central.patch.call_args[1]["payload"] == {"action": "logOnly"}


def test_patch_mdr_last_updated_at_only():
    central = MagicMock()
    central.patch.return_value = _rs(_cr(202, {}))
    patch_mdr_threat_feed_settings(central, "fw", last_updated_at="2020-01-01T00:00:00Z")
    assert central.patch.call_args[1]["payload"]["lastUpdatedAt"] == "2020-01-01T00:00:00Z"


def test_get_firewall_transaction_omits_fields_param():
    central = MagicMock()
    central.get_page.return_value = _rs(_cr(200, {"id": "tx"}))
    get_firewall_transaction(central, "fw", "tx1", fields=None)
    assert central.get_page.call_args[1]["params"] is None
