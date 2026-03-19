"""Tests for central.firewalls.licenses.methods."""

from unittest.mock import MagicMock

from central.classes import CentralResponse, ReturnState
from central.firewalls.licenses.methods import get_licenses


def test_get_licenses_success():
    central = MagicMock()
    lic = {
        "serialNumber": "S",
        "owner": {"id": "o", "type": "partner"},
        "partner": {"id": "p"},
        "tenant": {"id": "t"},
        "billingTenant": None,
        "model": "m",
        "modelType": "hardware",
        "licenses": [],
    }
    central.get.return_value = ReturnState(success=True, value=[lic])
    out = get_licenses(central, tenant_id="t", partner_id="p", sort="x")
    assert len(out) == 1


def test_get_licenses_failure():
    central = MagicMock()
    cr = CentralResponse(MagicMock(status_code=500, json=lambda: {}))
    central.get.return_value = ReturnState(success=False, value=cr)
    out = get_licenses(central)
    assert out.success is False


def test_get_licenses_skips_none():
    central = MagicMock()
    central.get.return_value = ReturnState(success=True, value=[None])
    out = get_licenses(central)
    assert len(out) == 0
