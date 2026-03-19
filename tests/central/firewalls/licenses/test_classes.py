"""Tests for central.firewalls.licenses.classes."""

from central.firewalls.licenses.classes import License, Licenses, Subscription


def test_subscription_and_license():
    sub = Subscription(
        id="1",
        licenseIdentifier="L",
        product={"code": "c", "name": "n", "genericCode": "g", "features": []},
        startDate="s",
        perpetual=False,
        type="term",
        quantity=1,
        usage={"current": {"count": 1, "date": None}},
    )
    assert sub.product is not None
    sub2 = Subscription(
        id="2",
        licenseIdentifier="L2",
        product=None,
        startDate="s",
        perpetual=False,
        type="trial",
        quantity=0,
        usage=None,
    )
    assert sub2.product is None

    lic = License(
        serialNumber="SN",
        owner={"id": "o", "type": "partner"},
        partner={"id": "p"},
        tenant={"id": "t"},
        billingTenant=None,
        model="m",
        modelType="hardware",
        licenses=[{"id": "s", "licenseIdentifier": "x", "product": None, "startDate": "s", "perpetual": True, "type": "perpetual", "quantity": 1, "usage": None}],
    )
    assert len(lic.licenses) == 1
    lic2 = License(
        serialNumber="S2",
        owner=None,
        partner=None,
        tenant=None,
        billingTenant=None,
        model="m",
        modelType="virtual",
        licenses=None,
        organization=None,
    )
    assert lic2.licenses == []

    L = Licenses([lic, lic2])
    assert L.get_license_by_serial_number("SN") is lic
    assert L.get_licenses_by_tenant_id("t") is None  # attr "tenant.id" not on License
