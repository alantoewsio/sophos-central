"""Tests for central.alerts.methods."""

from unittest.mock import MagicMock

from central.classes import CentralResponse, ReturnState
from central.alerts.methods import (
    get_alert,
    get_alerts,
    search_alerts,
    take_alert_action,
)


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


def test_search_alerts_success():
    central = MagicMock()
    cr = CentralResponse(
        MagicMock(
            status_code=200,
            json=lambda: {"items": [{"id": "a1"}], "pages": {}},
        )
    )
    central.post.return_value = ReturnState(success=True, value=cr)
    out = search_alerts(central, product=["firewall"], tenant_id="t")
    assert len(out) == 1
    assert central.post.call_args[1]["payload"]["product"] == ["firewall"]


def test_search_alerts_pagination():
    central = MagicMock()

    def post_side_effect(*args, **kwargs):
        call_n = getattr(post_side_effect, "n", 0)
        post_side_effect.n = call_n + 1
        if call_n == 0:
            body = {
                "items": [{"id": "1"}],
                "pages": {"nextKey": "k2"},
            }
        else:
            body = {"items": [{"id": "2"}], "pages": {}}
        cr = CentralResponse(MagicMock(status_code=200, json=lambda b=body: b))
        return ReturnState(success=True, value=cr)

    central.post.side_effect = post_side_effect
    out = search_alerts(central)
    assert len(out) == 2
    assert central.post.call_count == 2
    assert central.post.call_args_list[1][1]["payload"]["pageFromKey"] == "k2"


def test_search_alerts_second_page_fails():
    central = MagicMock()

    def post_side_effect(*args, **kwargs):
        call_n = getattr(post_side_effect, "n", 0)
        post_side_effect.n = call_n + 1
        if call_n == 0:
            body = {"items": [{"id": "1"}], "pages": {"nextKey": "k2"}}
            cr = CentralResponse(MagicMock(status_code=200, json=lambda b=body: b))
            return ReturnState(success=True, value=cr)
        cr = CentralResponse(MagicMock(status_code=500, json=lambda: {}))
        return ReturnState(success=False, value=cr)

    central.post.side_effect = post_side_effect
    out = search_alerts(central)
    assert out.success is False


def test_search_alerts_failure():
    central = MagicMock()
    cr = CentralResponse(MagicMock(status_code=400, json=lambda: {"error": "e"}))
    cr.error_message = "e"
    central.post.return_value = ReturnState(success=False, value=cr)
    out = search_alerts(central)
    assert out.success is False


def test_take_alert_action_success():
    central = MagicMock()
    body = {
        "id": "act-1",
        "alertId": "al-1",
        "action": "acknowledge",
        "status": "requested",
        "requestedAt": "2021-01-01T00:00:00Z",
    }
    cr = CentralResponse(MagicMock(status_code=201, json=lambda: body))
    central.post.return_value = ReturnState(success=True, value=cr)
    out = take_alert_action(central, "al-1", "acknowledge", tenant_id="t")
    assert out.action == "acknowledge"
    assert central.post.call_args[0][0] == "/common/v1/alerts/al-1/actions"


def test_take_alert_action_with_message():
    central = MagicMock()
    body = {
        "id": "x",
        "alertId": "y",
        "action": "cleanPua",
        "status": "requested",
        "requestedAt": "t",
    }
    cr = CentralResponse(MagicMock(status_code=201, json=lambda: body))
    central.post.return_value = ReturnState(success=True, value=cr)
    take_alert_action(central, "y", "cleanPua", message="m")
    assert central.post.call_args[1]["payload"] == {"action": "cleanPua", "message": "m"}


def test_take_alert_action_failure():
    central = MagicMock()
    cr = CentralResponse(MagicMock(status_code=403, json=lambda: {}))
    central.post.return_value = ReturnState(success=False, value=cr)
    out = take_alert_action(central, "x", "acknowledge")
    assert isinstance(out, ReturnState)


def test_take_alert_action_no_data():
    central = MagicMock()
    cr = CentralResponse(MagicMock(status_code=201, json=lambda: {}))
    central.post.return_value = ReturnState(success=True, value=cr)
    out = take_alert_action(central, "x", "acknowledge")
    assert isinstance(out, ReturnState)
