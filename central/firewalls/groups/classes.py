from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import List

from central.classes import CentralItems


@dataclass
class Group:
    id: str
    name: str
    parentGroup: ParentGroupID
    tenant: TenantID
    lockedByManagingAccount: bool
    firewalls: Firewalls
    configImport: ConfigImport
    createdBy: UserID
    createdAt: datetime
    updatedBy: UserID
    updatedAt: datetime


class Groups(CentralItems[Group]):
    def get_group_by_id(self, id: str) -> Group:
        return self.get_item_by_attr("id", id)

    def get_group_by_name(self, name: str) -> Group:
        return self.get_item_by_attr("name", name)

    def find_groups_by_name(self, search: str) -> List[Group] | None:
        return self.get_items_by_attr("name", search)

    def get_child_groups(self, parent_group_id: str) -> List[Group] | None:
        return self.get_items_by_attr("parentGroup.id", parent_group_id)

    def get_root_groups(self) -> List[Group] | None:
        root_groups = []
        for group in self._items:
            if group.parentGroup is None:
                root_groups.append(group)
        return root_groups if root_groups else None


@dataclass
class ParentGroupID:
    id: str


@dataclass
class TenantID:
    id: str


@dataclass
class FirewallID:
    id: str


@dataclass
class Firewalls:
    total: int
    itemsCount: int
    items: List[FirewallID]


@dataclass
class ConfigImport:
    sourceFirewall: FirewallID
    percentComplete: int
    status: str
    errors: List[str]


@dataclass
class UserID:
    id: str
    type: str
    name: str
    accountId: str
    accountType: str
