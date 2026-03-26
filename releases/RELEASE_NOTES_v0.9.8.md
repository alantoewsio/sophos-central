# Release v0.9.8

## Summary

Adds an **incremental** sync mode for `central-sync-to-db`: faster follow-up runs that refresh tenants (partner scope), firewalls, alerts since the last cached `raised_at`, and alert details only for newly seen alerts.

## Changes

- New `--incremental` CLI flag; full firmware polling remains the default and is documented as skipped in incremental mode.
- Shared `_sync_tenant_firewalls_alerts_and_details` used by full and incremental partner/tenant sync paths.
- New APIs: `sync_partner_incremental`, `sync_tenant_incremental`, and `sync_client_credentials_to_database_incremental`.
- Expanded unit tests for incremental flows, progress reporting, and API failure handling.
