# Firewall Config API Extensions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the SDK to wrap the upcoming Sophos Central Firewall Config APIs from `C:\Users\AlanToews\Downloads\firewall-config-docs\firewall-config-docs.html`.

**Architecture:** Keep the existing `central.firewalls.mdr` module because it already covers the MDR threat-feed endpoints in the attached OpenAPI document. Add a new `central.firewalls.config` package for firewall configuration export/import and cross-firewall transactions, using the same `ReturnState`, `CentralResponse`, status-message mapping, and mocked HTTP-test patterns used elsewhere in the SDK.

**Tech Stack:** Python 3.12, dataclasses, `requests` through `CentralSession`, `pytest`, `unittest.mock`.

---

## API Surface From The Attached Docs

The embedded OpenAPI document is `Firewall Management API` version `1.0.3`; its production server path includes `/firewall/v1/firewall-config`.

Already implemented in `central/firewalls/mdr/methods.py`:

- `GET /firewalls/{firewallId}/mdr-threat-feed`
- `PATCH /firewalls/{firewallId}/mdr-threat-feed/settings`
- `POST /firewalls/{firewallId}/mdr-threat-feed/indicators`
- `DELETE /firewalls/{firewallId}/mdr-threat-feed/indicators`
- `POST /firewalls/{firewallId}/mdr-threat-feed/indicators/delete`
- `POST /firewalls/{firewallId}/mdr-threat-feed/indicators/search`
- `GET /firewalls/{firewallId}/transactions/{transactionId}`

Missing APIs to add:

- `POST /firewalls/{firewallId}/export`
- `POST /firewalls/import`
- `POST /firewalls/import/{transactionId}/upload-complete`
- `GET /firewalls/transactions/{transactionId}`

## File Structure

- Create `central/firewalls/config/__init__.py` to expose the config package.
- Create `central/firewalls/config/classes.py` for typed response containers and request payload helpers:
  - `TransactionReference`
  - `PresignedUpload`
  - `TransactionQuery`
  - `Transaction`
  - `ExportConfigRequest`
  - `ImportUploadCompleteRequest`
- Create `central/firewalls/config/methods.py` for API wrappers:
  - `export_firewall_config`
  - `start_firewall_config_import`
  - `complete_firewall_config_import_upload`
  - `get_cross_firewall_transaction`
- Create `tests/central/firewalls/config/__init__.py`.
- Create `tests/central/firewalls/config/test_classes.py`.
- Create `tests/central/firewalls/config/test_methods.py`.
- Modify `README.md` with a short Firewall Config API section after the existing firewall examples.
- Modify `example.py` only if a lightweight non-destructive demo section fits the existing demo style; do not add any call that changes a real firewall by default.

### Task 1: Add Firewall Config Data Classes

**Files:**
- Create: `central/firewalls/config/__init__.py`
- Create: `central/firewalls/config/classes.py`
- Test: `tests/central/firewalls/config/test_classes.py`

- [ ] **Step 1: Write failing tests for response parsing and payload building**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/central/firewalls/config/test_classes.py -q`

Expected: import failure for `central.firewalls.config.classes`.

- [ ] **Step 3: Add package initializer**

```python
"""Firewall configuration import/export API wrappers."""
```

- [ ] **Step 4: Add class implementation**

```python
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class TransactionReference:
    transactionId: str

    def __init__(self, data: dict[str, Any]):
        self.transactionId = data["transactionId"]


@dataclass
class PresignedUpload:
    transactionId: str
    url: str
    method: str
    expiresAt: str

    def __init__(self, data: dict[str, Any]):
        self.transactionId = data["transactionId"]
        self.url = data["url"]
        self.method = data["method"]
        self.expiresAt = data["expiresAt"]


@dataclass
class TransactionQuery:
    key: str
    value: str


@dataclass
class TransactionRequest:
    method: str
    path: str
    query: list[TransactionQuery]

    def __init__(self, data: dict[str, Any]):
        self.method = data.get("method")
        self.path = data.get("path")
        self.query = [TransactionQuery(**item) for item in data.get("query", [])]


@dataclass
class Transaction:
    id: str
    status: Optional[str]
    result: Optional[str]
    createdAt: Optional[str]
    finishedAt: Optional[str]
    expiryAt: Optional[str]
    response: Optional[dict[str, Any]]
    request: Optional[TransactionRequest]

    def __init__(self, data: dict[str, Any]):
        self.id = data["id"]
        self.status = data.get("status")
        self.result = data.get("result")
        self.createdAt = data.get("createdAt")
        self.finishedAt = data.get("finishedAt")
        self.expiryAt = data.get("expiryAt")
        self.response = data.get("response")
        request = data.get("request")
        self.request = TransactionRequest(request) if request else None


@dataclass
class ExportConfigRequest:
    full_export: bool
    include_dependency: Optional[bool] = None
    export_entities: Optional[list[str]] = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"fullExport": self.full_export}
        if self.include_dependency is not None:
            payload["includeDependency"] = self.include_dependency
        if self.export_entities is not None:
            payload["exportEntities"] = self.export_entities
        return payload


@dataclass
class ImportUploadCompleteRequest:
    firewall_ids: list[str]
    checksum_md5: str
    file_size_bytes: int
    secure_master_key: Optional[str] = None
    perform_partial_import: Optional[bool] = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "firewallIds": self.firewall_ids,
            "checksumMd5": self.checksum_md5,
            "fileSizeBytes": self.file_size_bytes,
        }
        if self.secure_master_key is not None:
            payload["secureMasterKey"] = self.secure_master_key
        if self.perform_partial_import is not None:
            payload["performPartialImport"] = self.perform_partial_import
        return payload
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/central/firewalls/config/test_classes.py -q`

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add central/firewalls/config/__init__.py central/firewalls/config/classes.py tests/central/firewalls/config/__init__.py tests/central/firewalls/config/test_classes.py
git commit -m "feat: add firewall config API data classes"
```

### Task 2: Add Config Import/Export API Methods

**Files:**
- Create: `central/firewalls/config/methods.py`
- Test: `tests/central/firewalls/config/test_methods.py`

- [ ] **Step 1: Write failing tests for method paths, payloads, and parsed responses**

```python
from unittest.mock import MagicMock

from central.classes import CentralResponse, ReturnState
from central.firewalls.config.classes import PresignedUpload, Transaction, TransactionReference
from central.firewalls.config.methods import (
    complete_firewall_config_import_upload,
    export_firewall_config,
    get_cross_firewall_transaction,
    start_firewall_config_import,
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/central/firewalls/config/test_methods.py -q`

Expected: import failure for `central.firewalls.config.methods`.

- [ ] **Step 3: Add method implementation**

```python
from __future__ import annotations

import logging
from typing import Optional

from central.classes import ReturnState
from central.firewalls.config.classes import (
    ExportConfigRequest,
    ImportUploadCompleteRequest,
    PresignedUpload,
    Transaction,
    TransactionReference,
)
from central.session import CentralSession

logger = logging.getLogger(__name__)

_CONFIG_ROOT = "/firewall/v1/firewall-config/firewalls"
_ACCEPTED = {
    202: "Request accepted",
    400: "Bad request",
    401: "Authentication required",
    403: "Authorization required",
    404: "Resource not found",
    500: "Unexpected error",
}
_TRANSACTION = {
    200: "Transaction detail retrieved successfully",
    400: "Bad request",
    401: "Authentication required",
    403: "Authorization required",
    404: "Resource not found",
    409: "Conflict",
    500: "Unexpected error",
}


def _wrap_response(rs: ReturnState, status_messages: dict[int, str], parser=None) -> ReturnState:
    if rs.value is None:
        return ReturnState(success=False, message=rs.message or "Error: request failed")
    cr = rs.value
    if cr.success and parser is not None:
        cr.data = parser(cr.data)
    message = status_messages.get(cr.status_code, f"HTTP {cr.status_code}")
    if not cr.success:
        logger.debug("firewall config API status=%s", cr.status_code)
    return ReturnState(success=cr.success, message=message, value=cr)


def export_firewall_config(
    central: CentralSession,
    firewall_id: str,
    full_export: bool,
    include_dependency: Optional[bool] = None,
    export_entities: Optional[list[str]] = None,
    url_base: str = None,
    tenant_id: str = None,
    partner_id: str = None,
) -> ReturnState:
    request = ExportConfigRequest(
        full_export=full_export,
        include_dependency=include_dependency,
        export_entities=export_entities,
    )
    rs = central.post(
        f"{_CONFIG_ROOT}/{firewall_id}/export",
        payload=request.to_payload(),
        url_base=url_base,
        tenant_id=tenant_id,
        partner_id=partner_id,
    )
    return _wrap_response(rs, _ACCEPTED, TransactionReference)


def start_firewall_config_import(
    central: CentralSession,
    url_base: str = None,
    tenant_id: str = None,
    partner_id: str = None,
) -> ReturnState:
    rs = central.post(
        f"{_CONFIG_ROOT}/import",
        url_base=url_base,
        tenant_id=tenant_id,
        partner_id=partner_id,
    )
    return _wrap_response(rs, _ACCEPTED, PresignedUpload)


def complete_firewall_config_import_upload(
    central: CentralSession,
    transaction_id: str,
    firewall_ids: list[str],
    checksum_md5: str,
    file_size_bytes: int,
    secure_master_key: Optional[str] = None,
    perform_partial_import: Optional[bool] = None,
    url_base: str = None,
    tenant_id: str = None,
    partner_id: str = None,
) -> ReturnState:
    request = ImportUploadCompleteRequest(
        firewall_ids=firewall_ids,
        checksum_md5=checksum_md5,
        file_size_bytes=file_size_bytes,
        secure_master_key=secure_master_key,
        perform_partial_import=perform_partial_import,
    )
    rs = central.post(
        f"{_CONFIG_ROOT}/import/{transaction_id}/upload-complete",
        payload=request.to_payload(),
        url_base=url_base,
        tenant_id=tenant_id,
        partner_id=partner_id,
    )
    return _wrap_response(rs, _TRANSACTION, Transaction)


def get_cross_firewall_transaction(
    central: CentralSession,
    transaction_id: str,
    url_base: str = None,
    tenant_id: str = None,
    partner_id: str = None,
) -> ReturnState:
    rs = central.get_page(
        f"{_CONFIG_ROOT}/transactions/{transaction_id}",
        paginated=False,
        url_base=url_base,
        tenant_id=tenant_id,
        partner_id=partner_id,
    )
    return _wrap_response(rs, _TRANSACTION, Transaction)
```

- [ ] **Step 4: Run method tests**

Run: `pytest tests/central/firewalls/config/test_methods.py -q`

Expected: all tests pass.

- [ ] **Step 5: Run config package tests**

Run: `pytest tests/central/firewalls/config -q`

Expected: all config tests pass.

- [ ] **Step 6: Commit**

```bash
git add central/firewalls/config/methods.py tests/central/firewalls/config/test_methods.py
git commit -m "feat: add firewall config import export methods"
```

### Task 3: Re-check Existing MDR Coverage Against The Attached Docs

**Files:**
- Modify: `tests/central/firewalls/mdr/test_methods.py`
- Modify only if necessary: `central/firewalls/mdr/methods.py`

- [ ] **Step 1: Add regression tests for exact documented MDR payload names**

```python
def test_mdr_create_indicators_payload_matches_docs():
    central = MagicMock()
    central.post.return_value = _rs(_cr(202, {"transactionId": "tx"}))
    create_mdr_threat_feed_indicators(
        central,
        "fw-1",
        [{"value": "example.com", "type": "domain-name"}],
    )
    assert central.post.call_args[1]["payload"] == {
        "indicators": [{"value": "example.com", "type": "domain-name"}]
    }


def test_mdr_search_payload_matches_docs():
    central = MagicMock()
    central.post.return_value = _rs(_cr(202, {"transactionId": "tx"}))
    search_mdr_threat_feed_indicators(central, "fw-1", ["example.com"])
    assert central.post.call_args[1]["payload"] == {
        "indicatorValues": ["example.com"]
    }
```

- [ ] **Step 2: Run test to verify current behavior**

Run: `pytest tests/central/firewalls/mdr/test_methods.py -q`

Expected: all tests pass. If a payload-name assertion fails, fix only that wrapper payload.

- [ ] **Step 3: Commit if tests or code changed**

```bash
git add tests/central/firewalls/mdr/test_methods.py central/firewalls/mdr/methods.py
git commit -m "test: lock down mdr threat feed payloads"
```

### Task 4: Document The New SDK Surface

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add README usage text**

Add this section after the existing firewall API examples:

````markdown
**Firewall configuration import/export**

```python
from central.firewalls.config.methods import (
    complete_firewall_config_import_upload,
    export_firewall_config,
    get_cross_firewall_transaction,
    start_firewall_config_import,
)

# Export runs asynchronously and returns a transaction ID.
export_result = export_firewall_config(
    central,
    firewall_id="firewall-id",
    full_export=False,
    include_dependency=True,
    export_entities=["FirewallRule", "NATRule"],
    tenant_id=central.whoami.id,
    url_base=central.whoami.data_region_url(),
)
transaction_id = export_result.value.data.transactionId

# Import starts by requesting a pre-signed upload URL.
upload_result = start_firewall_config_import(
    central,
    tenant_id=central.whoami.id,
    url_base=central.whoami.data_region_url(),
)
upload = upload_result.value.data
print(upload.method, upload.url, upload.expiresAt)

# After uploading the archive to upload.url, complete the import.
complete_result = complete_firewall_config_import_upload(
    central,
    transaction_id=upload.transactionId,
    firewall_ids=["firewall-id"],
    checksum_md5="d41d8cd98f00b204e9800998ecf8427e",
    file_size_bytes=1024,
    tenant_id=central.whoami.id,
    url_base=central.whoami.data_region_url(),
)

# Poll cross-firewall transactions.
transaction = get_cross_firewall_transaction(
    central,
    transaction_id=upload.transactionId,
    tenant_id=central.whoami.id,
    url_base=central.whoami.data_region_url(),
)
print(transaction.value.data.status, transaction.value.data.result)
```
````

- [ ] **Step 2: Run README-related tests**

Run: `pytest tests/test_example.py -q`

Expected: pass. If this test imports README snippets indirectly, adjust the text to match package exports.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document firewall config import export APIs"
```

### Task 5: Full Verification

**Files:**
- No code changes expected.

- [ ] **Step 1: Run package-specific tests**

Run: `pytest tests/central/firewalls/config tests/central/firewalls/mdr -q`

Expected: pass.

- [ ] **Step 2: Run full test suite**

Run: `pytest -q`

Expected: pass with the repository coverage threshold.

- [ ] **Step 3: Run lint**

Run: `ruff check central tests`

Expected: no lint errors.

- [ ] **Step 4: Inspect final Git state**

Run: `git status --short --branch`

Expected: branch `codex/central-api-extensions-plan` or the implementation branch is ahead by the implementation commits, with only intentional files changed. Preserve pre-existing unrelated local changes (`.coverage`, `uv.lock`, `.cursor/`, `test.html`) unless the user explicitly asks to clean them.

## Self-Review

- Spec coverage: The plan covers all four missing import/export/cross-firewall transaction endpoints and verifies the seven MDR endpoints already present in `central.firewalls.mdr`.
- Placeholder scan: No implementation step depends on unspecified code.
- Type consistency: Method names, class names, payload field names, and response parser names are consistent across tasks.
