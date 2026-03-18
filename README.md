# sophos-central

CLI and Python API for [Sophos Central](https://www.sophos.com/products/central), including firewalls, licenses, alerts, and firmware management.

## Requirements

- Python 3.12+
- Sophos Central API credentials (client ID and client secret)

## Installation

```bash
pip install sophos-central
```

## Configuration

Create a `.env` or `credentials.env` in your working directory with:

- `CENTRAL-CLIENT-ID` – your Sophos Central API client ID  
- `CENTRAL-CLIENT-SECRET` – your Sophos Central API client secret  

## Usage

### CLI

After installation, the following commands are available:

- **sophos-central** – main CLI (firewalls, groups, licenses, firmware checks)
- **sophos-central-export-csv** – export data to CSV
- **sophos-central-sync-db** – sync data to SQLite (see [Sync to DB](#sync-to-db) below)

### Python API (SDK)

Create a session with your credentials, authenticate, then call the API methods. Methods return typed containers (e.g. `Firewalls`, `Licenses`, `Alerts`) on success, or `ReturnState` on failure—check with `isinstance(result, ReturnState)`.

**Session and authentication**

```python
from central.session import CentralSession
from central.classes import ReturnState

central = CentralSession(client_id="your-client-id", client_secret="your-client-secret")
auth = central.authenticate()
if not auth.success:
    raise SystemExit(auth.message)

# After auth, central.whoami is set (id, idType, apiHosts, etc.)
print(central.whoami.id, central.whoami.idType)  # e.g. tenant vs partner
```

**Firewalls**

```python
from central.session import CentralSession
from central.firewalls.methods import get_firewalls
from central.classes import ReturnState

central = CentralSession(client_id="...", client_secret="...")
central.authenticate()

# Current tenant (use whoami for tenant ID and data region URL)
url_base = central.whoami.data_region_url()
result = get_firewalls(central, tenant_id=central.whoami.id, url_base=url_base)

if isinstance(result, ReturnState) and not result.success:
    print("Error:", result.message)
else:
    for fw in result:
        print(fw.id, fw.name, fw.healthStatus)

# Optional: filter by group or search
result = get_firewalls(central, tenant_id=central.whoami.id, url_base=url_base, group_id="...", search="...")
```

**Firewall groups**

```python
from central.firewalls.groups.methods import get_firewall_groups

result = get_firewall_groups(
    central,
    tenant_id=central.whoami.id,
    url_base=url_base,
    recurseSubgroups=True,
    search="...",  # optional
)
for group in result:
    print(group.id, group.name)
```

**Licenses**

```python
from central.firewalls.licenses.methods import get_licenses

# Tenant-level licenses
result = get_licenses(
    central,
    tenant_id=central.whoami.id,
    url_base=url_base,
)
if not isinstance(result, ReturnState):
    for lic in result:
        print(lic.id, lic.name, lic.status)

# Partner-level (only when central.whoami.idType == "partner")
result = get_licenses(central, partner_id=central.whoami.id)
```

**Alerts**

```python
from central.alerts.methods import get_alerts, get_alert

# List alerts (firewall + other, optional time range)
result = get_alerts(
    central,
    tenant_id=central.whoami.id,
    url_base=url_base,
    product=["firewall", "other"],
    from_time="2025-01-01T00:00:00Z",  # ISO 8601
    to_time="2025-03-01T00:00:00Z",
    severity=["high", "medium"],
    page_size=100,
)
if not isinstance(result, ReturnState):
    for alert in result:
        print(alert.id, alert.raisedAt, alert.severity)

# Single alert by ID
detail = get_alert(central, alert_id="...", tenant_id=central.whoami.id, url_base=url_base)
if not isinstance(detail, ReturnState):
    print(detail.description, detail.products)
```

**Firmware upgrade check**

```python
from central.firewalls.firmware.methods import firmware_upgrade_check

result = firmware_upgrade_check(
    central,
    firewall_ids=["fw-uuid-1", "fw-uuid-2"],
    tenant_id=central.whoami.id,
    url_base=url_base,
)
if not isinstance(result, ReturnState):
    for fw in result.firewalls:
        print(fw.id, fw.upgradeAvailable)
    for ver in result.firmwareVersions:
        print(ver.version, ver.releaseDate)
```

**Partner: list tenants**

```python
# Only when central.whoami.idType == "partner"
tenants_result = central.get_tenants()
if isinstance(tenants_result, ReturnState) and not tenants_result.success:
    print(tenants_result.message)
else:
    for tenant in tenants_result:
        print(tenant.id, tenant.name, tenant.apiHost)
        # Use tenant.apiHost as url_base and tenant.id as tenant_id for tenant-scoped calls
```

**Using credentials from env**

```python
import os
from dotenv import dotenv_values

creds = dotenv_values(".env")  # or "credentials.env"
central = CentralSession(
    creds["CENTRAL-CLIENT-ID"],
    creds["CENTRAL-CLIENT-SECRET"],
)
central.authenticate()
# ... use SDK methods as above
```

---

### Sync to DB

The **sophos-central-sync-db** command (and `sync_to_db.py` when run locally) syncs Sophos Central data into a local SQLite database: tenants, firewalls, licenses, alerts, alert details, and firmware upgrade/version info. Existing rows are updated, new ones inserted. Useful for reporting, dashboards, or offline analysis.

**Invocation**

```bash
sophos-central-sync-db [OPTIONS]
```

Or from the project root:

```bash
uv run sync_to_db.py [OPTIONS]
python -m sync_to_db [OPTIONS]
```

**What gets synced**

- **Partner credentials** (`idType == "partner"`): all tenants, then per tenant: firewalls, licenses, alerts (firewall + other), alert details for new alerts, firmware upgrade check results; plus partner-level licenses.
- **Tenant credentials** (`idType == "tenant"`): single tenant (from whoami), firewalls, licenses, alerts, alert details, firmware upgrade info for that tenant.

Alerts are fetched incrementally when possible (from the latest `raisedAt` in the DB). Full alert details are fetched only for alerts that are new in the current run.

**Options**

| Option | Short | Description |
|--------|--------|-------------|
| `--log-level` | `-l` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`. Default: `INFO` (or env `LOG_LEVEL`). |
| `--db` | `-d` | Path to SQLite database file. Default: `sophos_central.db` in the current directory. |
| `--client-id` | — | Sophos Central client ID (must be used with `--client-secret`). |
| `--client-secret` | — | Sophos Central client secret (must be used with `--client-id`). |
| `--env` | `-e` | Path to a `.env` file with `CENTRAL-CLIENT-ID` and `CENTRAL-CLIENT-SECRET`. Can be repeated for multiple credential sets. |
| `--export-xlsx` | `-x` | After sync, export all summary tables to an Excel workbook (one sheet per table). Optional path; if omitted, uses `<db-stem>.xlsx` next to the DB. |

**Credentials (in order of precedence)**

1. **Inline:** `--client-id` and `--client-secret` (both required together).
2. **Env file(s):** `-e /path/to/file.env`. Multiple `-e` runs sync once per file (multiple credential sets).
3. **Default files:** `./credentials.env` or `./.env` in the current directory.

If no valid credentials are found, the script exits with an error.

**Examples**

```bash
# Default: use .env/credentials.env, write to sophos_central.db
sophos-central-sync-db

# Custom database path and log level
sophos-central-sync-db -d /data/sophos.db -l DEBUG

# Inline credentials
sophos-central-sync-db --client-id "..." --client-secret "..."

# Use a specific env file
sophos-central-sync-db -e ./prod.env

# Sync then export all tables to Excel (default path: sophos_central.xlsx)
sophos-central-sync-db -x

# Sync to a DB and export to a named Excel file
sophos-central-sync-db -d reports/sophos.db -x reports/sophos_export.xlsx

# Multiple env files = multiple sync runs into the same DB
sophos-central-sync-db -e tenant1.env -e tenant2.env
```

**Output**

- Logs: to stderr (or configured logging). Progress bar on a TTY.
- After each run: `sync_id`, then a per-table summary of rows added/updated and timing. If `-x` is used, a message that the workbook was written.

**Database schema**

The script creates/updates tables: `tenants`, `firewalls`, `licenses`, `license_subscriptions`, `alerts`, `alert_details`, `firmware_upgrades`, `firmware_versions`. Schema is managed by `central.db` (e.g. `init_schema`). The same tables are exported when using `--export-xlsx`.

---

## Development

Install with dev dependencies:

```bash
pip install -e ".[dev]"
```

Run the linter:

```bash
ruff check .
```

## License

APACHE 2.0
