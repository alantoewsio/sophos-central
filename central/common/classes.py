from __future__ import annotations

from typing import Any, List, Optional

from central.classes import CentralItems


class Role:
    """Tenant role from Common API ``GET /common/v1/roles``."""

    def __init__(self, data: dict):
        self.id = data.get("id", "")
        self.name = data.get("name", "")
        self.description = data.get("description")
        self.type = data.get("type", "")
        self.principalType = data.get("principalType", "")
        self.permissionSets: List[str] = list(data.get("permissionSets") or [])
        self.createdAt = data.get("createdAt")
        self.updatedAt = data.get("updatedAt")


class Roles(CentralItems[Role]):
    def get_role_by_id(self, role_id: str) -> Role | None:
        return self.get_item_by_attr("id", role_id)


class Admin:
    """Tenant admin from Common API ``GET /common/v1/admins``."""

    def __init__(self, data: dict):
        self.id = data.get("id", "")
        self.tenant: Optional[dict[str, Any]] = data.get("tenant")
        self.users: List[dict[str, Any]] = list(data.get("users") or [])
        self.profile: Optional[dict[str, Any]] = data.get("profile")
        self.roleAssignments: List[dict[str, Any]] = list(
            data.get("roleAssignments") or []
        )
        self.createdAt = data.get("createdAt")
        self.updatedAt = data.get("updatedAt")


class Admins(CentralItems[Admin]):
    def get_admin_by_id(self, admin_id: str) -> Admin | None:
        return self.get_item_by_attr("id", admin_id)
