from unittest.mock import MagicMock

from central.classes import CentralResponse, ReturnState
from central.firewalls.config.classes import (
    PresignedUpload,
    Transaction,
    TransactionReference,
)
from central.firewalls.config.methods import (
    complete_firewall_config_import_upload,
    export_firewall_config,
    get_cross_firewall_transaction,
    start_firewall_config_import,
    _wrap_response,
)


def _cr(code: int, data: dict | None = None):
    return CentralResponse(
        MagicMock(status_code=code, json=lambda: data if data is not None else {})
    )


def _rs(code: int, data: dict | None = None):
    cr = _cr(code, data)
    return ReturnState(success=cr.success, value=cr)


def test_export_firewall_config_posts_payload_and_returns_reference():
    central = MagicMock()
    central.post.return_value = _rs(202, {"transactionId": "tx-1"})
    out = export_firewall_config(
        central,
        "fw-1",
        full_export=False,
        include_dependency=True,
        export_entities=["FirewallRule"],
        tenant_id="tenant-1",
        partner_id="partner-1",
    )
    assert out.success
    assert isinstance(out.value.data, TransactionReference)
    central.post.assert_called_once_with(
        "/firewall/v1/firewall-config/firewalls/fw-1/export",
        payload={
            "fullExport": False,
            "includeDependency": True,
            "exportEntities": ["FirewallRule"],
        },
        url_base=None,
        tenant_id="tenant-1",
        partner_id="partner-1",
    )


def test_start_firewall_config_import_returns_presigned_upload():
    central = MagicMock()
    central.post.return_value = _rs(
        202,
        {
            "transactionId": "tx-1",
            "url": "https://upload.example.test/archive.zip",
            "method": "PUT",
            "expiresAt": "2026-06-23T18:00:00Z",
        },
    )
    out = start_firewall_config_import(central, tenant_id="tenant-1")
    assert out.success
    assert isinstance(out.value.data, PresignedUpload)
    central.post.assert_called_once_with(
        "/firewall/v1/firewall-config/firewalls/import",
        url_base=None,
        tenant_id="tenant-1",
        partner_id=None,
    )


def test_complete_firewall_config_import_upload_returns_transaction():
    central = MagicMock()
    central.post.return_value = _rs(
        200,
        {"id": "tx-1", "status": "started", "result": "notAvailable"},
    )
    out = complete_firewall_config_import_upload(
        central,
        "tx-1",
        firewall_ids=["fw-1"],
        checksum_md5="d41d8cd98f00b204e9800998ecf8427e",
        file_size_bytes=1024,
        perform_partial_import=True,
    )
    assert out.success
    assert isinstance(out.value.data, Transaction)
    assert central.post.call_args[1]["payload"]["performPartialImport"] is True


def test_get_cross_firewall_transaction_uses_get_page_without_pagination():
    central = MagicMock()
    central.get_page.return_value = _rs(
        200,
        {"id": "tx-1", "status": "finished", "result": "success"},
    )
    out = get_cross_firewall_transaction(central, "tx-1", tenant_id="tenant-1")
    assert out.success
    assert isinstance(out.value.data, Transaction)
    central.get_page.assert_called_once_with(
        "/firewall/v1/firewall-config/firewalls/transactions/tx-1",
        paginated=False,
        url_base=None,
        tenant_id="tenant-1",
        partner_id=None,
    )


def test_config_method_error_preserves_return_state():
    central = MagicMock()
    central.post.return_value = ReturnState(
        success=False,
        message="Error: not authenticated",
        value=None,
    )
    out = start_firewall_config_import(central)
    assert out.success is False
    assert out.message == "Error: not authenticated"


def test_config_method_http_error_uses_status_message():
    central = MagicMock()
    central.post.return_value = _rs(403, {"error": "denied"})
    out = start_firewall_config_import(central)
    assert out.success is False
    assert out.message == "Authorization required"


def test_wrap_response_without_parser_and_unknown_status():
    cr = _cr(299, {"ok": True})
    cr.success = True
    out = _wrap_response(ReturnState(success=True, value=cr), {})
    assert out.success is True
    assert out.message == "HTTP 299"
    assert out.value.data == {"ok": True}
