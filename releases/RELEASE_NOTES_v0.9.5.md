# Release v0.9.5

## Summary

Adds Sophos Central Common API helpers, expands SQLite sync and stale-data cleanup, and grows test coverage for DB and sync flows.

## Changes

- New `central.common` package with Common API v1 client helpers (`get_roles`, `get_admins`) and typed `Role` / `Admin` collections
- Database layer: additional stale-row deletion paths (tenant roles, tenant admins, partner tenants, related cascades) and change logging for data rows
- `sync_to_db` updates to align with the broader schema and sync behavior
- Tests for `central.common` and extended coverage for `db` and `sync_to_db`
- Version bump and release notes
