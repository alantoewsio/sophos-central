"""Tests for central.alerts.methods."""

from unittest.mock import MagicMock

from central.classes import CentralResponse, ReturnState
from central.alerts.methods import get_alert, get_alerts


def test_get_alerts_success():
    central = MagicMock()
    central.get.return_value = ReturnState(success=True, value=[{"id": "a1", "product": "firewall"}])
    out = get_alerts(central, product=["firewall"], tenant_id="t")
    assert len(out) == 1


def test_get_alerts_failure():
    central = MagicMock()
    r = MagicMock(status_code=400, json=lambda: {}, error_message="e")
    cr = CentralResponse(MagicMock(status_code=400, json=lambda: {"error": "e"}))
    cr.error_message = "e"
    central.get.return_value = ReturnState(success=False, value=cr)
    out = get_alerts(central)
    assert out.success is False


def test_get_alerts_empty_items():
    central = MagicMock()
    central.get.return_value = ReturnState(success=True, value=None)
    out = get_alerts(central)
    assert len(out) == 0


def test_get_alert_success():
    central = MagicMock()
    d = {"id": "x", "category": "c"}
    cr = CentralResponse(MagicMock(status_code=200, json=lambda: d))
    central.get_page.return_value = ReturnState(success=True, value=cr)
    out = get_alert(central, "x")
    assert out.id == "x"


def test_get_alert_page_fail():
    central = MagicMock()
    cr = CentralResponse(MagicMock(status_code=404, json=lambda: {}))
    central.get_page.return_value = ReturnState(success=False, value=cr)
    out = get_alert(central, "x")
    assert isinstance(out, ReturnState)


def test_get_alert_no_data():
    central = MagicMock()
    m = MagicMock(status_code=200, json=lambda: {})
    m.data = None
    cr = CentralResponse.__new__(CentralResponse)
    cr.success = True
    cr.data = None
    cr.status_code = 200
    central.get_page.return_value = ReturnState(success=True, value=m)
    out = get_alert(central, "x")
    assert isinstance(out, ReturnState)
