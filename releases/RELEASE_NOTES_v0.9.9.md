# Release v0.9.9

## Summary

Incremental sync now includes firmware upgrade checks and version catalog updates, with correct client-wide pruning after partner multi-tenant runs.

## Changes

- Run firmware upgrade checks during incremental tenant and partner sync; persist upgrade rows and `firmwareVersions` like full sync.
- Partner incremental sync aggregates firmware version keys across tenants and prunes stale `firmware_versions` once per client (avoids dropping versions present only on other tenants).
- Single-tenant paths still prune stale firmware versions immediately after a successful API response.
- Incremental progress totals and labels include a firmware step (`--incremental` help text updated).
- Tests cover partner aggregate/prune, firmware API failure handling, and incremental progress/elapsed behavior.
