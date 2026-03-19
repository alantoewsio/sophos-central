"""Additional central.session coverage."""

from unittest.mock import MagicMock, patch

from central.classes import ReturnState
from central.session import CentralSession


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_do_get_tenants_not_authenticated(mock_get, mock_post):
    s = CentralSession("a", "b")
    s.auth = None
    s.authenticate = lambda: ReturnState(success=False)
    r = s._do_get_tenants()
    assert r.success is False


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_page_when_not_authenticated(mock_get, mock_post):
    s = CentralSession("a", "b")
    s.auth = None
    s.authenticate = lambda: ReturnState(success=False)
    r = s.get_page("/x")
    assert r.success is False


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_patch_post_delete_unauthenticated(mock_get, mock_post):
    s = CentralSession("a", "b")
    s.auth = None
    s.authenticate = lambda: ReturnState(success=False)
    assert s.patch("/p").success is False
    assert s.post("/p").success is False
    assert s.delete("/p").success is False


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_add_headers_no_jwt(mock_get, mock_post):
    mock_post.return_value = MagicMock(status_code=200, json=lambda: {"access_token": "t", "expires_in": 3600})
    mock_get.return_value = MagicMock(
        status_code=200,
        json=lambda: {
            "id": "x",
            "idType": "tenant",
            "apiHosts": {"global": "https://g/", "dataRegion": "https://d/"},
        },
    )
    s = CentralSession("a", "b")
    s.authenticate()
    s.jwt = None
    h = s._add_base_headers()
    assert "Authorization" not in h


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_pagination_next_key_exhausted(mock_get, mock_post):
    """Cover branch where nextKey becomes None after a page."""
    from types import SimpleNamespace

    mock_post.return_value = MagicMock(status_code=200, json=lambda: {"access_token": "t", "expires_in": 3600})
    mock_get.side_effect = [
        MagicMock(status_code=200, json=lambda: {
            "id": "x", "idType": "tenant",
            "apiHosts": {"global": "https://g/", "dataRegion": "https://d/"},
        }),
        MagicMock(status_code=200, json=lambda: {
            "items": [{"a": 1}],
            "pages": {"nextKey": "k1"},
        }),
        MagicMock(status_code=200, json=lambda: {
            "items": [{"a": 2}],
            "pages": {},
        }),
    ]
    s = CentralSession("a", "b")
    s.authenticate()
    r = s.get("/alerts", paginated=False)
    assert r.success is True
    assert len(r.value) == 2


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_first_page_items_none(mock_get, mock_post):
    mock_post.return_value = MagicMock(status_code=200, json=lambda: {"access_token": "t", "expires_in": 3600})
    mock_get.return_value = MagicMock(
        status_code=200,
        json=lambda: {
            "id": "x",
            "idType": "tenant",
            "apiHosts": {"dataRegion": "https://d/"},
        },
    )
    s = CentralSession("a", "b")
    s.authenticate()
    mock_get.return_value = MagicMock(
        status_code=200,
        json=lambda: {"pages": {"current": 1, "total": 1, "size": 10, "maxSize": 100}},
    )
    r = s.get("/p", paginated=True)
    assert r.success is True
    assert r.value == []


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_page_number_pagination_branch(mock_get, mock_post):
    """Cover 204->262: pages without nextKey use page-number pagination."""
    mock_post.return_value = MagicMock(status_code=200, json=lambda: {"access_token": "t", "expires_in": 3600})
    mock_get.side_effect = [
        MagicMock(status_code=200, json=lambda: {
            "id": "x", "idType": "tenant",
            "apiHosts": {"global": "https://g/", "dataRegion": "https://d/"},
        }),
        MagicMock(status_code=200, json=lambda: {
            "items": [{"i": 1}],
            "pages": {"current": 1, "total": 2, "size": 10, "maxSize": 100},
        }),
        MagicMock(status_code=200, json=lambda: {
            "items": [{"i": 2}],
            "pages": {"current": 2, "total": 2, "size": 10, "maxSize": 100},
        }),
    ]
    s = CentralSession("a", "b")
    s.authenticate()
    r = s.get("/list", paginated=True)
    assert r.success is True
    assert len(r.value) == 2


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_next_key_page_empty_items(mock_get, mock_post):
    """Cover 226->228: nextKey present but result.value.items is empty."""
    mock_post.return_value = MagicMock(status_code=200, json=lambda: {"access_token": "t", "expires_in": 3600})
    mock_get.side_effect = [
        MagicMock(status_code=200, json=lambda: {
            "id": "x", "idType": "tenant",
            "apiHosts": {"global": "https://g/", "dataRegion": "https://d/"},
        }),
        MagicMock(status_code=200, json=lambda: {
            "items": [{"a": 1}],
            "pages": {"nextKey": "k2"},
        }),
        MagicMock(status_code=200, json=lambda: {
            "items": [],
            "pages": {},
        }),
    ]
    s = CentralSession("a", "b")
    s.authenticate()
    r = s.get("/alerts", paginated=False)
    assert r.success is True
    assert len(r.value) == 1


@patch("central.session.requests.post")
@patch("central.session.requests.get")
def test_get_no_pages_skips_pagination_block(mock_get, mock_post):
    """Cover 204->262: result has no pages (or pages falsy), skip pagination block."""
    mock_post.return_value = MagicMock(status_code=200, json=lambda: {"access_token": "t", "expires_in": 3600})
    mock_get.side_effect = [
        MagicMock(status_code=200, json=lambda: {
            "id": "x", "idType": "tenant",
            "apiHosts": {"global": "https://g/", "dataRegion": "https://d/"},
        }),
        MagicMock(status_code=200, json=lambda: {"items": [{"a": 1}]}),
    ]
    s = CentralSession("a", "b")
    s.authenticate()
    r = s.get("/list", paginated=True)
    assert r.success is True
    assert len(r.value) == 1
