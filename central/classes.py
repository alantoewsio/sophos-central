from __future__ import annotations
from ast import TypeVar
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
import types
from typing import List, Literal, Optional
import requests

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CentralItems[T]:
    _items: List[T]

    @property
    def success(self) -> bool:
        return True

    @property
    def value(self) -> List[T]:
        return self._items

    @property
    def message(self) -> str:
        return None

    def count(self) -> int:
        return len(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __init__(self, items: List[Tenant]):
        self._items = items

    def _is_iterable(self) -> bool:
        try:
            iter(self._items)
            return True
        except TypeError:
            return False

    def __iter__(self):
        if self._is_iterable():
            return iter(self._items)
        return iter([])

    def get_item_by_attr(self, attr: str, value: str) -> object | None:
        for item in self._items:
            if hasattr(item, attr) and getattr(item, attr) == value:
                return item
        return None

    def get_items_by_attr(self, attr: str, value: str) -> List[object] | None:
        items = []
        for item in self._items:
            if hasattr(item, attr) and getattr(item, attr) == value:
                items.append(item)
        return items if items else None


@dataclass
class ReturnState:
    success: bool
    value: Optional[object] = None
    message: Optional[str] = None

    def _is_iterable(self) -> bool:
        try:
            iter(self.value)
            return True
        except TypeError:
            return False

    def __iter__(self):
        if self._is_iterable():
            return iter(self.value)
        return iter([])

    def __bool__(self) -> bool:
        return self.success

    def __len__(self) -> int:
        if self._is_iterable():
            return len(self.value)
        return 0


@dataclass
class CentralResponse:
    success: bool
    status_code: int
    data: object
    error_message: Optional[str] = None
    pages: Optional[types.SimpleNamespace] = None
    items: Optional[types.SimpleNamespace] = None

    def __init__(self, response: requests.Response):
        self.status_code = response.status_code
        self.success = 200 <= response.status_code <= 299
        self.error_message = None
        self.pages = None
        self.items = None
        self.data = None

        if not response:
            self.success = False
            self.error_message = "Invalid response"

        try:
            self.data = response.json()
            if "pages" in self.data:
                logger.trace("Response pages: %s", self.data["pages"])
                self.pages = PaginationResponse(**self.data["pages"])
            if "items" in self.data:
                self.items = self.data["items"]
        except ValueError:
            logger.error("Invalid JSON in response: %s", response.text[:200])
            self.error_message = response.text


@dataclass
class Partner:
    id: str


@dataclass
class Organization:
    id: str


@dataclass
class Product:
    code: str


@dataclass
class Address:
    address1: str
    address2: str
    city: str
    state: str
    countryCode: str
    postalCode: str


class Contact:
    firstName: str
    lastName: str
    email: str
    phone: str
    address: Address


@dataclass
class Tenant:
    id: str
    showAs: str
    name: str
    dataGeography: str
    dataRegion: str
    billingType: str
    partner: Partner
    organization: Organization
    apiHost: str
    status: str
    contact: Contact
    externalIds: Optional[List[str]] = None
    products: Optional[List[Product]] = None


class Tenants(CentralItems[Tenant]):
    def get_tenant_by_id(self, id: str) -> Tenant | None:
        for tenant in self._items:
            if tenant.id == id:
                return tenant
        return None

    def get_tenant_by_name(self, name: str) -> Tenant | None:
        for tenant in self._items:
            if (
                tenant.name.casefold() == name.casefold()
                or tenant.showAs.casefold() == name.casefold()
            ):
                return tenant
        return None

    def find_tenantss_by_name(self, search: str) -> List[Tenant] | None:
        tenants = []
        for tenant in self._items:
            if (
                search.casefold() in tenant.name.casefold()
                or search.casefold() in tenant.showAs.casefold()
            ):
                tenants.append(tenant)
        return tenants if tenants else None

    def get_tenants_by_region(self, region: str) -> List[Tenant] | None:
        tenants = []
        for tenant in self._items:
            if region.casefold() == tenant.dataRegion.casefold():
                tenants.append(tenant)
        return tenants if tenants else None

    def get_tenants_by_billingType(self, billingType: str) -> List[Tenant] | None:
        tenants = []
        for tenant in self._items:
            if billingType.casefold() == tenant.billingType.casefold():
                tenants.append(tenant)
        return tenants if tenants else None

    def get_tenants_by_product(self, product_code: str) -> List[Tenant] | None:
        tenants = []
        for tenant in self._items:
            codes = [product.code.casefold() for product in tenant.products]
            if product_code.casefold() in codes:
                tenants.append(tenant)
        return tenants if tenants else None

    def get_tenants_by_status(self, status: str) -> List[Tenant] | None:
        tenants = [
            tenant
            for tenant in self._items
            if tenant.status.casefold() == status.casefold()
        ]
        return tenants if tenants else None

    def get_tenants_by_organization(self, organization_id: str) -> List[Tenant] | None:
        tenants = [
            tenant
            for tenant in self._items
            if tenant.organization.id == organization_id
        ]
        return tenants if tenants else None


@dataclass
class PaginationRequest:
    page: int = 1
    pageTotal: bool = False
    pageSize: int = 100


@dataclass
class PaginationResponse:
    current: int
    size: int
    maxSize: int
    items: Optional[int] = None
    total: Optional[int] = 1


class AuthenticationResponse:
    access_token: str
    errorCode: str
    expires_in: int = 3600
    message: str
    refresh_token: str
    token_type: str
    trackingId: str
    _timestamp: datetime = datetime.now()

    def __init__(
        self,
        access_token: Optional[str] = None,
        expires_in: Optional[int] = None,
        message: Optional[str] = None,
        refresh_token: Optional[str] = None,
        token_type: Optional[str] = None,
        trackingId: Optional[str] = None,
        errorCode: Optional[str] = None,
    ):
        self.access_token = access_token
        self.expires_in = expires_in
        self.message = message
        self.refresh_token = refresh_token
        self.token_type = token_type
        self.trackingId = trackingId
        self._timestamp = datetime.now()

    def is_valid(self) -> bool:
        if not self.access_token:
            return False
        return self._timestamp + timedelta(seconds=self.expires_in) > datetime.now()

    def __bool__(self) -> bool:
        return self.is_valid()


@dataclass
class WhoamiResponse:
    id: str
    idType: Literal["partner", "tenant", "organization"]
    apiHosts: dict[Literal["global", "dataRegion"], str]

    def global_url(self) -> str:
        if "global" not in self.apiHosts:
            return None
        return self.apiHosts["global"]

    def data_region_url(self) -> str:
        if "dataRegion" not in self.apiHosts:
            return None
        return self.apiHosts["dataRegion"]
