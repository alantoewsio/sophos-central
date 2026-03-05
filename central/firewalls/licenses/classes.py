from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import List, Literal, Optional

from central.classes import CentralItems


@dataclass
class Owner:
    id: str
    type: Literal["partner", "organization"]


@dataclass
class EntityID:
    id: str  # Entity uuid


@dataclass
class UsageCurrent:
    count: int
    date: Optional[datetime] = None
    collectedAt: Optional[datetime] = None


@dataclass
class Usage:
    current: UsageCurrent


@dataclass
class Product:
    code: str
    name: str
    genericCode: str
    features: List[str]


# @dataclass
class Subscription:
    id: str
    licenseIdentifier: str
    product: Product
    startDate: str
    perpetual: bool
    type: Literal["trial", "term", "usage", "ordered", "enterprise", "perpetual"]
    quantity: int
    usage: Usage
    endDate: Optional[str] = None
    unlimited: Optional[bool] = False

    def __init__(
        self,
        id: str,
        licenseIdentifier: str,
        product: dict,
        startDate: str,
        perpetual: bool,
        type: Literal["trial", "term", "usage", "ordered", "enterprise", "perpetual"],
        quantity: int,
        usage: dict,
        endDate: Optional[str] = None,
        unlimited: Optional[bool] = False,
    ):
        self.id = id
        self.licenseIdentifier = licenseIdentifier
        self.product = Product(**product) if product else None
        self.startDate = startDate
        self.endDate = endDate
        self.perpetual = perpetual
        self.type = type
        self.quantity = quantity
        self.usage = Usage(UsageCurrent(**usage["current"])) if usage else None
        self.unlimited = unlimited


class License:
    serialNumber: str  # Firewall serial number
    owner: Owner
    organization: EntityID
    partner: EntityID
    tenant: EntityID
    model: str
    modelType: Literal["virtual", "hardware"]
    licenses: Optional[List[Subscription]] = None
    billingTenant: Optional[EntityID] = None
    lastSeenAt: Optional[str] = None

    def __init__(
        self,
        serialNumber: str,
        owner: dict,
        partner: dict,
        tenant: dict,
        billingTenant: dict,
        model: str,
        modelType: Literal["virtual", "hardware"],
        licenses: List[Subscription],
        organization: Optional[dict] = None,
        lastSeenAt: Optional[str] = None,
    ):
        self.serialNumber = serialNumber
        self.owner = Owner(**owner) if owner else None
        self.organization = EntityID(**organization) if organization else None
        self.partner = EntityID(**partner) if partner else None
        self.tenant = EntityID(**tenant) if tenant else None
        self.billingTenant = EntityID(**billingTenant) if billingTenant else None
        self.model = model
        self.modelType = modelType
        self.licenses = (
            [Subscription(**license) for license in licenses] if licenses else []
        )

        self.lastSeenAt = lastSeenAt


class Licenses(CentralItems[License]):
    def get_license_by_serial_number(self, serial_number: str) -> License | None:
        return self.get_item_by_attr("serialNumber", serial_number)

    def get_licenses_by_tenant_id(self, tenant_id: str) -> List[License] | None:
        return self.get_items_by_attr("tenant.id", tenant_id)
