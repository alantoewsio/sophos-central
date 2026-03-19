"""Extra coverage for central.alerts.methods optional parameters."""

from unittest.mock import MagicMock

from central.classes import ReturnState
from central.alerts.methods import get_alert, get_alerts


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
