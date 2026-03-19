# sfos-central-sdk

CLI and Python API for [Sophos Central](https://www.sophos.com/products/central), including firewalls, licenses, alerts, and firmware management.

## Requirements

- Python 3.12+
- Sophos Central API credentials (client ID and client secret)

## Installation

```bash
pip install sfos-central-sdk
```

## Configuration

Create a `.env` or `credentials.env` in your working directory with:

- `CENTRAL-CLIENT-ID` – your Sophos Central API client ID  
- `CENTRAL-CLIENT-SECRET` – your Sophos Central API client secret  

## Usage

### CLI

After installation, the **central-sync-to-db** command syncs data to SQLite; use `--export-xlsx` to export all tables to Excel after sync (see [Sync to DB](#sync-to-db)).

The repo includes **`example.py`**: run `python example.py` (or `uv run python example.py`) from the project root with `.env` / `credentials.env` for a demo of firewalls, groups, licenses, and firmware checks via the Python API.

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

The **central-sync-to-db** command (module `central.sync_to_db`) syncs Sophos Central data into a local SQLite database: tenants, firewalls, licenses, alerts, alert details, and firmware upgrade/version info. Existing rows are updated, new ones inserted. Every synced table includes `client_id` (the `CENTRAL-CLIENT-ID` / OAuth client that last wrote the row), which helps when combining data from several credentials. Useful for reporting, dashboards, or offline analysis.

**Invocation**

```bash
central-sync-to-db [OPTIONS]
```

Or as a module:

```bash
uv run python -m central.sync_to_db [OPTIONS]
python -m central.sync_to_db [OPTIONS]
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
central-sync-to-db

# Custom database path and log level
central-sync-to-db -d /data/sophos.db -l DEBUG

# Inline credentials
central-sync-to-db --client-id "..." --client-secret "..."

# Use a specific env file
central-sync-to-db -e ./prod.env

# Sync then export all tables to Excel (default path: sophos_central.xlsx)
central-sync-to-db -x

# Sync to a DB and export to a named Excel file
central-sync-to-db -d reports/sophos.db -x reports/sophos_export.xlsx

# Multiple env files = multiple sync runs into the same DB
central-sync-to-db -e tenant1.env -e tenant2.env
```

**Output**

- Logs: to stderr (or configured logging). Progress bar on a TTY.
- After each run: `sync_id`, then a per-table summary of rows added/updated and timing. If `-x` is used, a message that the workbook was written.

**Database schema**

The script creates/updates tables: `tenants`, `firewalls`, `licenses`, `license_subscriptions`, `alerts`, `alert_details`, `firmware_upgrades`, `firmware_versions`. Schema is managed by `central.db` (e.g. `init_schema`). The same tables are exported when using `--export-xlsx`.

**Programmatic sync (shared DB connection)**

If you already have an open SQLite connection and credentials, import from `central.sync_to_db`:

```python
from central.db import get_connection, init_schema
from central.sync_to_db import (
    sync_client_credentials_to_database,
    CentralSyncAuthError,
)

conn = get_connection("sophos_central.db")
init_schema(conn)
try:
    result = sync_client_credentials_to_database(
        conn, client_id, client_secret
    )  # default quiet=True: no progress bar or console log lines from the sync
    # result.sync_id, result.summary, result.elapsed_by_table, result.total_elapsed
finally:
    conn.close()
```

On auth failure, `CentralSyncAuthError` is raised. Use `quiet=False` (and optional `progress=SyncProgress()` from `central.sync_to_db`) to mirror CLI logging/progress.

**Note (v0.2+):** The sync CLI/API lives under `central.sync_to_db`. Replace former `from sync_to_db import …` with `from central.sync_to_db import …`.

---

## Development

Install with dev dependencies:

```bash
pip install -e ".[dev]"
# or with uv (matches CI):
uv sync --extra dev
```

Run the linter:

```bash
ruff check .
```

### Security scanning (no cost)

- **Dependency vulnerabilities:** [pip-audit](https://pypi.org/project/pip-audit/) checks installed packages against the [Python Packaging Advisory Database](https://github.com/pypa/advisory-database). Run:
  ```bash
  uv run pip-audit
  ```
- **Code security:** [Bandit](https://bandit.readthedocs.io/) is included in dev dependencies. Run:
  ```bash
  uv run bandit -c pyproject.toml -r central example.py
  ```
- **CI:** The repo includes a GitHub Actions workflow (`.github/workflows/security.yml`) that runs pip-audit and Bandit on push/PR to `master`/`main` and weekly on a schedule. Free for public repos; private repos get a monthly Actions allowance.

## Licensing

This project is licensed under the Apache License 2.0 (see [License](#license) below). Third-party dependencies and their licenses are listed below.

### Runtime dependencies

| Package   | Version  | License   |
|----------|----------|-----------|
| dotenv   | ≥0.9.9   | Unspecified on PyPI (thin wrapper; depends on **python-dotenv**, BSD-3-Clause) |
| openpyxl | ≥3.1.0   | MIT       |
| requests | ≥2.32.5  | Apache-2.0 |

### Dev dependencies

| Package       | Version  | License    |
|---------------|----------|------------|
| ruff          | ≥0.15.0  | MIT        |
| pytest        | ≥8.0.0   | MIT        |
| pytest-cov    | ≥5.0.0   | MIT        |
| bandit[toml]  | ≥1.7.0   | Apache-2.0 |
| pip-audit     | ≥2.0.0   | Apache-2.0 |

## License

APACHE 2.0
