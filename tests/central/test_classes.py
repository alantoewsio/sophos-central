"""Tests for central.classes."""

from __future__ import annotations

import types
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from central.classes import (
    AuthenticationResponse,
    CentralItems,
    CentralResponse,
    PaginationResponse,
    ReturnState,
    Tenant,
    Tenants,
    WhoamiResponse,
)


def test_central_items_value_and_message():
    ci = CentralItems([])
    assert ci.value == []
    assert ci.message is None


def test_central_items_iteration_and_helpers():
    t = Tenant(
        id="1",
        showAs="A",
        name="Alpha",
        dataGeography="US",
        dataRegion="us-east",
        billingType="monthly",
        partner=types.SimpleNamespace(id="p"),
        organization=types.SimpleNamespace(id="o"),
        apiHost="https://api.example",
        status="active",
        contact=None,
        externalIds=[],
        products=[],
    )
    items = CentralItems([t])
    assert items.success is True
    assert len(items) == 1
    assert items.count() == 1
    assert list(items) == [t]
    assert items.get_item_by_attr("id", "1") is t
    assert items.get_item_by_attr("id", "x") is None
    assert items.get_items_by_attr("id", "1") == [t]
    assert items.get_items_by_attr("id", "none") is None


def test_central_items_non_iterable_items():
    class BadItems(CentralItems):
        def __init__(self):
            self._items = 123  # not iterable

    b = BadItems()
    assert list(iter(b)) == []


def test_return_state():
    rs = ReturnState(success=True, value=[1, 2])
    assert bool(rs) is True
    assert len(rs) == 2
    assert list(rs) == [1, 2]

    rs2 = ReturnState(success=False, value=123)
    assert bool(rs2) is False
    assert len(rs2) == 0
    assert list(rs2) == []


def test_central_response_success_with_items():
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"items": [{"a": 1}]}
    cr = CentralResponse(r)
    assert cr.success is True
    assert cr.items == [{"a": 1}]


def test_central_response_pages_next_key():
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"pages": {"nextKey": "k1", "fromKey": "f"}}
    cr = CentralResponse(r)
    assert cr.pages.nextKey == "k1"


def test_central_response_pages_offset_pagination():
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {
        "pages": {"current": 1, "size": 10, "maxSize": 100, "total": 5},
        "items": [],
    }
    cr = CentralResponse(r)
    assert isinstance(cr.pages, PaginationResponse)
    assert cr.pages.current == 1


def test_central_response_pages_other():
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"pages": {"foo": "bar"}}
    cr = CentralResponse(r)
    assert cr.pages.foo == "bar"


def test_central_response_invalid_json():
    r = MagicMock()
    r.status_code = 200
    r.text = "not json" * 50
    r.json.side_effect = ValueError()
    cr = CentralResponse(r)
    assert cr.error_message is not None


def test_central_response_falsy_request():
    class Falsy:
        __slots__ = ("status_code", "text")

        def __init__(self):
            self.status_code = 0
            self.text = ""

        def __bool__(self):
            return False

        def json(self):
            raise ValueError()

    cr = CentralResponse(Falsy())
    assert cr.success is False
    # json() raises; error_message becomes response.text
    assert cr.error_message == ""


def test_whoami_urls():
    w = WhoamiResponse(
        id="t1",
        idType="tenant",
        apiHosts={"global": "https://g/", "dataRegion": "https://d/"},
    )
    assert w.global_url() == "https://g/"
    assert w.data_region_url() == "https://d/"
    w2 = WhoamiResponse(id="x", idType="tenant", apiHosts={})
    assert w2.global_url() is None
    assert w2.data_region_url() is None


def test_tenants_helpers():
    t1 = Tenant(
        id="1",
        showAs="Show1",
        name="Name1",
        dataGeography="US",
        dataRegion="r1",
        billingType="b1",
        partner=types.SimpleNamespace(id="p1"),
        organization=types.SimpleNamespace(id="o1"),
        apiHost="h",
        status="Active",
        contact=None,
        externalIds=[],
        products=[types.SimpleNamespace(code="FW")],
    )
    t2 = Tenant(
        id="2",
        showAs="Other",
        name="Other",
        dataGeography="US",
        dataRegion="r2",
        billingType="b2",
        partner=types.SimpleNamespace(id="p1"),
        organization=types.SimpleNamespace(id="o2"),
        apiHost="h",
        status="inactive",
        contact=None,
        externalIds=[],
        products=[types.SimpleNamespace(code="xgw")],
    )
    tenants = Tenants([t1, t2])
    assert tenants.get_tenant_by_id("1") is t1
    assert tenants.get_tenant_by_id("x") is None
    assert tenants.get_tenant_by_name("name1") is t1
    assert tenants.get_tenant_by_name("show1") is t1
    t3 = Tenant(
        id="3",
        showAs="OnlyShow",
        name="Different",
        dataGeography="US",
        dataRegion="r",
        billingType="b",
        partner=types.SimpleNamespace(id="p"),
        organization=types.SimpleNamespace(id="o"),
        apiHost="h",
        status="s",
        contact=None,
        externalIds=[],
        products=[],
    )
    assert Tenants([t3]).get_tenant_by_name("onlyshow") is t3
    assert Tenants([t1, t2]).get_tenant_by_name("nonexistent") is None
    t_show_only = Tenant(
        id="4",
        showAs="ByShowOnly",
        name="OtherName",
        dataGeography="US",
        dataRegion="r",
        billingType="b",
        partner=types.SimpleNamespace(id="p"),
        organization=types.SimpleNamespace(id="o"),
        apiHost="h",
        status="s",
        contact=None,
        externalIds=[],
        products=[],
    )
    assert Tenants([t_show_only]).get_tenant_by_name("byshowonly") is t_show_only
    assert tenants.find_tenantss_by_name("ame") == [t1]
    assert tenants.find_tenantss_by_name("zzz") is None
    assert tenants.get_tenants_by_region("R1") == [t1]
    assert tenants.get_tenants_by_billingType("b2") == [t2]
    assert tenants.get_tenants_by_product("fw") == [t1]
    assert tenants.get_tenants_by_status("active") == [t1]
    assert tenants.get_tenants_by_organization("o1") == [t1]


def test_authentication_response():
    a = AuthenticationResponse(access_token="t", expires_in=3600)
    assert a.is_valid() is True
    assert bool(a) is True
    a2 = AuthenticationResponse(access_token=None)
    assert a2.is_valid() is False
    a3 = AuthenticationResponse(access_token="t", expires_in=-999999)
    assert a3.is_valid() is False
