"""Tests for central.session.CentralSession."""

from __future__ import annotations

import types
from unittest.mock import MagicMock, patch

import pytest

from central.classes import CentralResponse, ReturnState
from central.session import CentralSession


def _auth_json():
    return {
        "access_token": "jwt",
        "expires_in": 3600,
        "token_type": "Bearer",
    }


def _whoami_partner():
    return {
        "id": "partner-1",
        "idType": "partner",
        "apiHosts": {"global": "https://api.example.com/"},
    }


def _whoami_tenant():
    return {
        "id": "tenant-1",
        "idType": "tenant",
        "apiHosts": {
            "global": "https://g/",
            "dataRegion": "https://tenant.example.com/",
        },
    }


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_authenticate_missing_creds(mock_get, mock_post):
    s = CentralSession(None, None)
    r = s._do_authenticate()
    assert r.success is False
    mock_post.assert_not_called()


@patch("central.session.requests.post")
def test_authenticate_http_error(mock_post):
    mock_post.return_value = MagicMock(status_code=401, text="nope")
    s = CentralSession("id", "sec")
    r = s._do_authenticate()
    assert r.success is False


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_whoami_without_jwt_raises(mock_get, mock_post):
    s = CentralSession("id", "sec")
    s.jwt = None
    with pytest.raises(Exception, match="JWT"):
        s._do_whoami()


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_whoami_http_error(mock_get, mock_post):
    mock_post.return_value = MagicMock(status_code=200, json=lambda: _auth_json())
    mock_get.return_value = MagicMock(status_code=500, text="err")
    s = CentralSession("id", "sec")
    s._do_authenticate()
    r = s._do_whoami()
    assert r.success is False


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_authenticate_full_flow(mock_get, mock_post):
    mock_post.return_value = MagicMock(status_code=200, json=lambda: _auth_json())
    mock_get.return_value = MagicMock(status_code=200, json=lambda: _whoami_tenant())
    s = CentralSession("id", "sec")
    r = s.authenticate()
    assert r.success is True
    assert s.whoami.id == "tenant-1"


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_authenticate_short_circuit_when_auth_set(mock_get, mock_post):
    s = CentralSession("id", "sec")
    s.auth = types.SimpleNamespace()
    s.whoami = types.SimpleNamespace(
        id="t", idType="tenant", apiHosts={"dataRegion": "https://x/"}
    )
    r = s.authenticate()
    assert r.success is True
    mock_post.assert_not_called()


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_authenticate_auth_fails_bool(mock_get, mock_post):
    mock_post.return_value = MagicMock(status_code=401, text="bad")
    s = CentralSession("id", "sec")
    r = s.authenticate()
    assert r.success is False


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_tenants_rejects_tenant_account(mock_get, mock_post):
    mock_post.return_value = MagicMock(status_code=200, json=lambda: _auth_json())
    mock_get.return_value = MagicMock(status_code=200, json=lambda: _whoami_tenant())
    s = CentralSession("id", "sec")
    s.authenticate()
    out = s.get_tenants()
    assert isinstance(out, ReturnState)
    assert out.success is False


def _tenant_item(tid="t1"):
    return {
        "id": tid,
        "name": "T",
        "showAs": "T",
        "dataGeography": "US",
        "dataRegion": "us",
        "billingType": "monthly",
        "partner": {"id": "p"},
        "organization": {"id": "o"},
        "apiHost": "https://h/",
        "status": "active",
        "contact": None,
        "externalIds": [],
        "products": [],
    }


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_tenants_partner_success(mock_get, mock_post):
    mock_post.return_value = MagicMock(status_code=200, json=lambda: _auth_json())
    mock_get.side_effect = [
        MagicMock(status_code=200, json=lambda: _whoami_partner()),
        MagicMock(
            status_code=200,
            json=lambda: {
                "items": [_tenant_item()],
                "pages": {"current": 1, "total": 1, "size": 50, "maxSize": 100},
            },
        ),
    ]
    s = CentralSession("id", "sec")
    s.authenticate()
    tenants = s.get_tenants()
    assert hasattr(tenants, "_items")
    assert len(tenants) == 1


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_not_authenticated(mock_get, mock_post):
    s = CentralSession("id", "sec")
    s.auth = None
    s.authenticate = lambda: ReturnState(success=False)
    r = s.get("/x")
    assert r.success is False


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_page_success(mock_get, mock_post):
    mock_post.return_value = MagicMock(status_code=200, json=lambda: _auth_json())
    mock_get.return_value = MagicMock(status_code=200, json=lambda: _whoami_tenant())
    s = CentralSession("id", "sec")
    s.authenticate()
    mock_get.return_value = MagicMock(
        status_code=200,
        json=lambda: {"items": [1], "pages": {"current": 1, "total": 1}},
    )
    r = s.get_page("/path", paginated=False)
    assert r.success is True


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_with_next_key_pagination(mock_get, mock_post):
    mock_post.return_value = MagicMock(status_code=200, json=lambda: _auth_json())
    whoami = MagicMock(status_code=200, json=lambda: _whoami_tenant())
    page1 = MagicMock(
        status_code=200,
        json=lambda: {
            "items": [{"a": 1}],
            "pages": {"nextKey": "k2"},
        },
    )
    page2 = MagicMock(
        status_code=200,
        json=lambda: {"items": [{"a": 2}], "pages": {}},
    )
    mock_get.side_effect = [whoami, page1, page2]
    s = CentralSession("id", "sec")
    s.authenticate()
    r = s.get("/common/v1/alerts", paginated=False)
    assert r.success is True
    assert len(r.value) == 2


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_next_page_fails(mock_get, mock_post):
    mock_post.return_value = MagicMock(status_code=200, json=lambda: _auth_json())
    whoami = MagicMock(status_code=200, json=lambda: _whoami_tenant())
    page1 = MagicMock(
        status_code=200,
        json=lambda: {"items": [1], "pages": {"nextKey": "k"}},
    )
    page2 = MagicMock(status_code=500, text="fail")
    mock_get.side_effect = [whoami, page1, page2]
    s = CentralSession("id", "sec")
    s.authenticate()
    r = s.get("/x", paginated=False)
    assert r.success is False


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_numeric_pagination(mock_get, mock_post):
    mock_post.return_value = MagicMock(status_code=200, json=lambda: _auth_json())
    whoami = MagicMock(status_code=200, json=lambda: _whoami_tenant())
    page = {"size": 10, "maxSize": 100, "total": 3}
    p1 = MagicMock(
        status_code=200,
        json=lambda: {"items": [{"i": 1}], "pages": {**page, "current": 1}},
    )
    p2 = MagicMock(
        status_code=200,
        json=lambda: {"items": [{"i": 2}], "pages": {**page, "current": 2}},
    )
    p3 = MagicMock(
        status_code=200,
        json=lambda: {"items": [{"i": 3}], "pages": {**page, "current": 3}},
    )
    mock_get.side_effect = [whoami, p1, p2, p3]
    s = CentralSession("id", "sec")
    s.authenticate()
    r = s.get("/list", paginated=True)
    assert r.success is True
    assert len(r.value) == 3


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_numeric_page_error(mock_get, mock_post):
    mock_post.return_value = MagicMock(status_code=200, json=lambda: _auth_json())
    whoami = MagicMock(status_code=200, json=lambda: _whoami_tenant())
    page = {"size": 10, "maxSize": 100, "total": 2}
    p1 = MagicMock(
        status_code=200,
        json=lambda: {"items": [1], "pages": {**page, "current": 1}},
    )
    p2 = MagicMock(status_code=400, json=lambda: {})
    mock_get.side_effect = [whoami, p1, p2]
    s = CentralSession("id", "sec")
    s.authenticate()
    r = s.get("/list", paginated=True)
    assert r.success is False


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_url_with_params_tenant(mock_get, mock_post):
    mock_post.return_value = MagicMock(status_code=200, json=lambda: _auth_json())
    mock_get.return_value = MagicMock(status_code=200, json=lambda: _whoami_tenant())
    s = CentralSession("id", "sec")
    s.authenticate()
    url = s._get_url("/p", params={"a": 1, "b": [1, 2]})
    assert "/p?" in url
    assert "a=1" in url


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_add_base_headers(mock_get, mock_post):
    mock_post.return_value = MagicMock(status_code=200, json=lambda: _auth_json())
    mock_get.return_value = MagicMock(status_code=200, json=lambda: _whoami_tenant())
    s = CentralSession("id", "sec")
    s.authenticate()
    s.jwt = "tok"
    h = s._add_base_headers(
        tenant_id="t", partner_id="p", organization_id="o", X_Custom="v"
    )
    assert "Authorization" in h
    assert h["X-Tenant-ID"] == "t"


@patch("central.session.requests.post")
@patch("central.session.requests.patch")
@patch("central.session.requests.get")
def test_patch_post_delete(mock_get, mock_patch, mock_post):
    mock_post.side_effect = [
        MagicMock(status_code=200, json=lambda: _auth_json()),
        MagicMock(status_code=204, json=lambda: {}),
    ]
    mock_get.return_value = MagicMock(status_code=200, json=lambda: _whoami_tenant())
    mock_patch.return_value = MagicMock(status_code=200, json=lambda: {})
    del_mock = MagicMock(return_value=MagicMock(status_code=200, json=lambda: {}))
    s = CentralSession("id", "sec")
    s.authenticate()
    with patch("central.session.requests.delete", del_mock):
        s.patch("/p", payload={})
        s.post("/p2", payload={})
        s.delete("/p3", payload={})
    mock_patch.assert_called_once()
    assert mock_post.call_count >= 2
    del_mock.assert_called_once()


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_tenants_not_found_after_empty_do_get(mock_get, mock_post):
    """When _do_get_tenants returns False (e.g. get fails), expect error state."""
    mock_post.return_value = MagicMock(status_code=200, json=lambda: _auth_json())
    mock_get.side_effect = [
        MagicMock(status_code=200, json=lambda: _whoami_partner()),
        MagicMock(status_code=500, text="fail"),
    ]
    s = CentralSession("id", "sec")
    s.authenticate()
    out = s.get_tenants()
    assert isinstance(out, ReturnState)
    assert out.success is False
