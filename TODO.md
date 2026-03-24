# Firewall Management API coverage

Source: [Firewall Management API Guide](https://developer.sophos.com/firewall-management) (see also [API reference](https://developer.sophos.com/docs/firewall-v1/1/overview)).

Legend: `[x]` implemented in this repo · `[ ]` not implemented

## Firewall operations

- [x] **List firewalls** — `GET /firewall/v1/firewalls` — `central/firewalls/methods.py` → `get_firewalls`
- [x] **Perform action on firewall** — `POST /firewall/v1/firewalls/{firewallId}/action` (e.g. `approveManagement`) — `approve_management`
- [x] **Change firewall attributes** — `PATCH /firewall/v1/firewalls/{firewallId}` — `set_firewall_location_and_label`
- [x] **Delete firewall** — `DELETE /firewall/v1/firewalls/{firewallId}` — `delete_firewall`
- [x] **Check firmware upgrades** — `POST /firewall/v1/firewalls/actions/firmware-upgrade-check` — `firmware_upgrade_check` in `central/firewalls/methods.py` and `central/firewalls/firmware/methods.py`
- [x] **Upgrade firmware** — `POST /firewall/v1/firewalls/actions/firmware-upgrade` — `schedule_firmware_upgrade` (`methods.py`) and `upgrade_firmware` (`firewall/firmware/methods.py`)
- [x] **Cancel firmware upgrade** — `DELETE /firewall/v1/firewalls/actions/firmware-upgrade` — `cancel_firmware_upgrade` in both `methods.py` and `firewall/firmware/methods.py`

## Firewall group operations

- [x] **List firewall groups** — `GET /firewall/v1/firewall-groups` — `central/firewalls/groups/methods.py` → `get_firewall_groups`
- [x] **Create firewall group** — `POST /firewall/v1/firewall-groups` — `create_firewall_group`
- [x] **Update firewall group** — `PATCH /firewall/v1/firewall-groups/{groupId}` — `update_firewall_group`
- [x] **Delete firewall group** — `DELETE /firewall/v1/firewall-groups/{groupId}` — `delete_firewall_group`
- [x] **Get firewall synchronization status** — `GET /firewall/v1/firewall-groups/{groupId}/firewalls/sync-status` — `get_firewall_group_sync_status`

## MDR operations

Per the [Firewall API OpenAPI](https://developer.sophos.com/docs/firewall-v1/1/overview), these live under **`/firewall/v1/firewall-config/firewalls/{firewallId}/...`** (not under `/firewall/v1/firewalls/...`). Implemented in `central/firewalls/mdr/methods.py`.

- [x] **Retrieve MDR threat feed** — `GET .../mdr-threat-feed` (returns `transactionId`; poll transaction endpoint) — `get_mdr_threat_feed`
- [x] **Patch MDR threat feed settings** — `PATCH .../mdr-threat-feed/settings` — `patch_mdr_threat_feed_settings`
- [x] **Create MDR threat feed indicators** — `POST .../mdr-threat-feed/indicators` — `create_mdr_threat_feed_indicators`
- [x] **Delete all MDR threat feed indicators** — `DELETE .../mdr-threat-feed/indicators` — `delete_all_mdr_threat_feed_indicators`
- [x] **Delete given MDR threat feed indicators** — `POST .../mdr-threat-feed/indicators/delete` — `delete_mdr_threat_feed_indicators`
- [x] **Search MDR threat feed indicators** — `POST .../mdr-threat-feed/indicators/search` — `search_mdr_threat_feed_indicators`
- [x] **Retrieve transaction** — `GET .../transactions/{transactionId}` — `get_firewall_transaction`

---

*Out of scope for this checklist: other Sophos Central APIs used elsewhere (e.g. `central/alerts/methods.py` → `/common/v1/alerts`, `central/firewalls/licenses/methods.py` → `/licenses/v1/licenses/firewalls`).*
