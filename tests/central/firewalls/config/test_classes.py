from central.firewalls.config.classes import (
    ExportConfigRequest,
    ImportUploadCompleteRequest,
    PresignedUpload,
    Transaction,
    TransactionReference,
)


def test_transaction_reference_parses_transaction_id():
    ref = TransactionReference({"transactionId": "tx-1"})
    assert ref.transactionId == "tx-1"


def test_presigned_upload_parses_required_fields():
    upload = PresignedUpload(
        {
            "transactionId": "tx-1",
            "url": "https://upload.example.test/archive.zip",
            "method": "PUT",
            "expiresAt": "2026-06-23T18:00:00Z",
        }
    )
    assert upload.transactionId == "tx-1"
    assert upload.method == "PUT"


def test_transaction_parses_optional_request_query():
    tx = Transaction(
        {
            "id": "tx-1",
            "status": "finished",
            "result": "success",
            "createdAt": "2026-06-23T17:00:00Z",
            "finishedAt": "2026-06-23T17:01:00Z",
            "expiryAt": "2026-06-24T17:00:00Z",
            "response": {"ok": True},
            "request": {
                "method": "POST",
                "path": "/firewalls/import",
                "query": [{"key": "fields", "value": "response"}],
            },
        }
    )
    assert tx.id == "tx-1"
    assert tx.request.query[0].key == "fields"


def test_transaction_allows_null_request_query():
    tx = Transaction(
        {
            "id": "tx-1",
            "status": "finished",
            "result": "success",
            "request": {
                "method": "POST",
                "path": "/firewalls/fw-1/export",
                "query": None,
            },
        }
    )
    assert tx.request.query == []


def test_export_config_request_full_export_payload():
    request = ExportConfigRequest(full_export=True)
    assert request.to_payload() == {"fullExport": True}


def test_export_config_request_partial_payload():
    request = ExportConfigRequest(
        full_export=False,
        include_dependency=True,
        export_entities=["FirewallRule", "NATRule"],
    )
    assert request.to_payload() == {
        "fullExport": False,
        "includeDependency": True,
        "exportEntities": ["FirewallRule", "NATRule"],
    }


def test_import_upload_complete_request_payload():
    request = ImportUploadCompleteRequest(
        firewall_ids=["fw-1"],
        checksum_md5="d41d8cd98f00b204e9800998ecf8427e",
        file_size_bytes=1024,
        secure_master_key="secret",
        perform_partial_import=False,
    )
    assert request.to_payload() == {
        "firewallIds": ["fw-1"],
        "checksumMd5": "d41d8cd98f00b204e9800998ecf8427e",
        "fileSizeBytes": 1024,
        "secureMasterKey": "secret",
        "performPartialImport": False,
    }


def test_import_upload_complete_request_required_only_payload():
    request = ImportUploadCompleteRequest(
        firewall_ids=["fw-1"],
        checksum_md5="d41d8cd98f00b204e9800998ecf8427e",
        file_size_bytes=1024,
    )
    assert request.to_payload() == {
        "firewallIds": ["fw-1"],
        "checksumMd5": "d41d8cd98f00b204e9800998ecf8427e",
        "fileSizeBytes": 1024,
    }
