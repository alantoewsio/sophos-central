from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional

from central.classes import CentralItems


@dataclass
class ManagedAgent:
    id: str
    type: str
    name: Optional[str] = None

    def __init__(self, data: dict):
        self.id = data.get("id", "")
        self.type = data.get("type", "")
        self.name = data.get("name")


@dataclass
class Person:
    id: str
    name: Optional[str] = None

    def __init__(self, data: dict):
        self.id = data.get("id", "")
        self.name = data.get("name")


@dataclass
class TenantRef:
    id: str
    name: str

    def __init__(self, data: dict):
        self.id = data.get("id", "")
        self.name = data.get("name", "")


class Alert:
    """Alert from Sophos Central Common API."""

    def __init__(self, data: dict):
        self.id = data.get("id", "")
        self.allowedActions = data.get("allowedActions") or []
        self.category = data.get("category", "")
        self.description = data.get("description", "")
        self.groupKey = data.get("groupKey", "")
        self.managedAgent = (
            ManagedAgent(data["managedAgent"]) if data.get("managedAgent") else None
        )
        self.person = Person(data["person"]) if data.get("person") else None
        self.product = data.get("product", "")
        self.raisedAt = data.get("raisedAt", "")
        self.severity = data.get("severity", "")
        self.tenant = TenantRef(data["tenant"]) if data.get("tenant") else None
        self.type = data.get("type", "")


class AlertActionResult:
    """Response from POST /common/v1/alerts/{alertId}/actions (201)."""

    def __init__(self, data: dict):
        self.id = data.get("id", "")
        self.alertId = data.get("alertId", "")
        self.action = data.get("action", "")
        self.status = data.get("status", "")
        self.requestedAt = data.get("requestedAt", "")
        self.completedAt = data.get("completedAt")


class Alerts(CentralItems[Alert]):
    def get_alert_by_id(self, id: str) -> Alert | None:
        return self.get_item_by_attr("id", id)

    def get_alerts_by_severity(self, severity: str) -> List[Alert] | None:
        return self.get_items_by_attr("severity", severity)

    def get_alerts_by_category(self, category: str) -> List[Alert] | None:
        return self.get_items_by_attr("category", category)

    def get_alerts_by_product(self, product: str) -> List[Alert] | None:
        return self.get_items_by_attr("product", product)
