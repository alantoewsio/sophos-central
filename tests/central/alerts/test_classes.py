"""Tests for central.alerts.classes."""

from central.alerts.classes import (
    Alert,
    AlertActionResult,
    Alerts,
    ManagedAgent,
    Person,
    TenantRef,
)


def test_managed_agent_person_tenant_ref():
    assert ManagedAgent({}).id == ""
    assert Person({"id": "p"}).name is None
    assert TenantRef({}).id == ""


def test_alert_action_result():
    r = AlertActionResult(
        {
            "id": "i",
            "alertId": "a",
            "action": "acknowledge",
            "status": "completed",
            "requestedAt": "t0",
            "completedAt": "t1",
        }
    )
    assert r.id == "i" and r.alertId == "a" and r.completedAt == "t1"


def test_alert_and_alerts():
    a = Alert(
        {
            "id": "1",
            "allowedActions": [],
            "managedAgent": {"id": "m", "type": "t"},
            "person": {"id": "p"},
            "tenant": {"id": "t", "name": "n"},
        }
    )
    assert a.managedAgent is not None
    assert a.person is not None
    assert a.tenant is not None
    b = Alert({"id": "2"})
    assert b.managedAgent is None
    al = Alerts([a, b])
    assert al.get_alert_by_id("1") is a
    assert al.get_alerts_by_severity(a.severity) is not None
    assert al.get_alerts_by_category(a.category) is not None
    assert al.get_alerts_by_product(a.product) is not None
