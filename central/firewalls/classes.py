from __future__ import annotations
from dataclasses import dataclass
from typing import List

from central.classes import CentralItems


@dataclass
class Firewall:
    id: str
    cluster: Cluster
    tenant: Tenant
    serialNumber: str
    group: Group
    hostname: str
    name: str
    externalIpv4Addresses: List[str]
    firmwareVersion: str
    model: str
    status: Status
    stateChangedAt: str
    capabilities: List[str]
    geoLocation: GeoLocation
    createdBy: CreatedBy
    createdAt: str
    updatedAt: str
    updatedBy: UpdatedBy

    def __init__(self, data: dict):

        self.id = data["id"]
        if not data["cluster"]:
            self.cluster = None
        else:
            self.cluster = Cluster(**data["cluster"])
        self.tenant = Tenant(**data["tenant"])
        self.serialNumber = data["serialNumber"]
        if not data["group"]:
            self.group = None
        else:
            self.group = Group(**data["group"])
        self.hostname = data["hostname"]
        self.name = data["name"]
        self.externalIpv4Addresses = data["externalIpv4Addresses"]
        self.firmwareVersion = data["firmwareVersion"]
        self.model = data["model"]
        self.status = Status(**data["status"])
        self.stateChangedAt = data["stateChangedAt"]
        self.capabilities = data["capabilities"]
        if not data["geoLocation"]:
            self.geoLocation = None
        else:
            self.geoLocation = GeoLocation(**data["geoLocation"])
        self.createdBy = CreatedBy(**data["createdBy"])
        self.createdAt = data["createdAt"]
        self.updatedAt = data["updatedAt"]
        self.updatedBy = UpdatedBy(**data["updatedBy"])


class Firewalls(CentralItems[Firewall]):
    def get_firewall_by_id(self, id: str) -> Firewall | None:
        return self.get_item_by_attr("id", id)

    def get_firewall_by_name(self, name: str) -> Firewall | None:
        return self.get_item_by_attr("name", name)

    def find_firewalls_by_name(self, search: str) -> List[Firewall] | None:
        return self.get_items_by_attr("name", search)

    def get_firewalls_by_group_id(self, id: str) -> List[Firewall] | None:
        return self.get_items_by_attr("group.id", id)

    def get_firewalls_by_group_name(self, name: str) -> List[Firewall] | None:
        return self.get_items_by_attr("group.name", name)


@dataclass
class Cluster:
    id: str
    mode: str
    status: str
    peers: Peers


@dataclass
class Peers:
    id: str
    serialNumber: str


@dataclass
class Tenant:
    id: str


@dataclass
class Group:
    id: str
    name: str


@dataclass
class Status:
    managingStatus: str
    reportingStatus: str
    connected: bool
    suspended: bool


@dataclass
class GeoLocation:
    latitude: str
    longitude: str


@dataclass
class CreatedBy:
    id: str
    type: str
    name: str
    accountType: str
    accountId: str


@dataclass
class UpdatedBy:
    id: str
    type: str
    name: str
    accountType: str
    accountId: str
