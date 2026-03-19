"""Additional central.db coverage."""

import central.db as db


def test_upsert_tenant_contact_exception_path(db_conn):
    """Contact object whose __dict__ is not dict-like triggers except str(contact)."""
    class BadContact:
        @property
        def __dict__(self):
            return [1, 2, 3]

    db.upsert_tenant(
        db_conn,
        {
            "id": "tc",
            "name": "n",
            "contact": BadContact(),
        },
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="t",
    )


def test_upsert_tenant_contact_dict_without_get(db_conn):
    class M:
        __dict__ = {"x": 1}

    db.upsert_tenant(
        db_conn,
        {"id": "tx", "name": "n", "contact": M()},
        client_id="oauth-cid",
        update_id="u",
        run_timestamp="t",
    )


def test_upsert_license_usage_date_string(db_conn):
    from types import SimpleNamespace

    sub = SimpleNamespace(
        id="s1",
        licenseIdentifier="L",
        product=None,
        startDate="s",
        endDate=None,
        perpetual=False,
        type="term",
        quantity=1,
        usage=SimpleNamespace(
            current=SimpleNamespace(count=1, date="2024-01-01")
        ),
        unlimited=False,
    )
    lic = SimpleNamespace(
        serialNumber="SER3",
        tenant=None,
        partner=None,
        organization=None,
        model="m",
        modelType="hardware",
        licenses=[sub],
    )
    db.upsert_license(
        db_conn, lic, client_id="oauth-cid", update_id="u", run_timestamp="t"
    )
