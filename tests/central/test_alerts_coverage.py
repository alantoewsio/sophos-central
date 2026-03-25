"""Extra coverage for central.alerts.methods optional parameters."""

from unittest.mock import MagicMock

from central.classes import ReturnState
from central.alerts.methods import get_alert, get_alerts, search_alerts


def test_get_alerts_all_query_params():
    central = MagicMock()
    central.get.return_value = ReturnState(success=True, value=[{"id": "1"}])
    get_alerts(
        central,
        group_key="g",
        from_time="a",
        to_time="b",
        sort=["x"],
        product=["p"],
        category=["c"],
        severity=["s"],
        ids=["i"],
        fields=["f"],
        page_size=2000,
        page_total=False,
        tenant_id="t",
    )
    call_kw = central.get.call_args[1]
    assert call_kw["params"]["groupKey"] == "g"
    assert call_kw["params"]["pageSize"] == 1000


def test_get_alert_with_fields():
    central = MagicMock()
    from central.classes import CentralResponse

    cr = CentralResponse(MagicMock(status_code=200, json=lambda: {"id": "z"}))
    central.get_page.return_value = ReturnState(success=True, value=cr)
    get_alert(central, "aid", fields=["a"], tenant_id="t")


def test_search_alerts_all_body_fields():
    central = MagicMock()
    from central.classes import CentralResponse

    cr = CentralResponse(MagicMock(status_code=200, json=lambda: {"items": [], "pages": {}}))
    central.post.return_value = ReturnState(success=True, value=cr)
    search_alerts(
        central,
        group_key="g",
        from_time="a",
        to_time="b",
        sort=["raisedAt:desc"],
        product=["firewall"],
        category=["malware"],
        severity=["high"],
        ids=["550e8400-e29b-41d4-a716-446655440000"],
        fields=["id"],
        page_size=2000,
        page_total=False,
        url_base="https://example.test/",
        tenant_id="t",
    )
    p = central.post.call_args[1]["payload"]
    assert p["groupKey"] == "g"
    assert p["from"] == "a"
    assert p["to"] == "b"
    assert p["sort"] == ["raisedAt:desc"]
    assert p["product"] == ["firewall"]
    assert p["category"] == ["malware"]
    assert p["severity"] == ["high"]
    assert p["ids"] == ["550e8400-e29b-41d4-a716-446655440000"]
    assert p["fields"] == ["id"]
    assert p["pageSize"] == 1000
    assert p["pageTotal"] is False


def test_search_alerts_no_items_key():
    """Response without ``items`` uses cr.items is None branch."""
    central = MagicMock()
    from central.classes import CentralResponse

    cr = CentralResponse(MagicMock(status_code=200, json=lambda: {"pages": {}}))
    central.post.return_value = ReturnState(success=True, value=cr)
    out = search_alerts(central)
    assert len(out) == 0
