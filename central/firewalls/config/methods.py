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


def _wrap_response(
    rs: ReturnState, status_messages: dict[int, str], parser=None
) -> ReturnState:
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
