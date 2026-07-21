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
        self.query = [TransactionQuery(**item) for item in data.get("query") or []]


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
