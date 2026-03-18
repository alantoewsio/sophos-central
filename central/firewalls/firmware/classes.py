from __future__ import annotations
from dataclasses import dataclass
import datetime
from typing import List, Literal, Optional

from central.classes import CentralItems


@dataclass
class FirewallUpgrade:
    id: str
    serialNumber: str
    firmwareVersion: str
    upgradeToVersion: List[str]


@dataclass
class FirmwareVersion:
    bugs: List[str]
    news: List[str]
    size: str
    version: str


# @dataclass
class FirewallUpgradeInfo:
    firewalls: CentralItems[FirewallUpgrade]
    firmwareVersions: CentralItems[FirmwareVersion]

    def __init__(self, firewalls: dict, firmwareVersions: dict):
        self.firewalls = [FirewallUpgrade(**firewall) for firewall in firewalls]
        self.firmwareVersions = [
            FirmwareVersion(**firmware) for firmware in firmwareVersions
        ]

    @property
    def success(self) -> Literal[True]:
        return True

    def list_available_upgrades(self) -> CentralItems[FirewallUpgrade]:
        return CentralItems[FirewallUpgrade](
            [upgrade for upgrade in self.firewalls if upgrade.upgradeToVersion]
        )

    def count_available_upgrades(self) -> int:
        return self.list_available_upgrades().count()


@dataclass
class FirmwareUpgrade:
    id: str
    upgradeToVersion: str
    upgradeAt: Optional[datetime] = None

    def __dict__(self) -> dict:
        result = {
            "id": self.id,
            "upgradeToVersion": self.upgradeToVersion,
        }
        if self.upgradeAt:
            # upgradeAt needs to be a string in format "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
            result["upgradeAt"] = self.upgradeAt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return result
