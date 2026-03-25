# Release v0.9.7

## Summary

Fixes incremental alert sync so alerts are not skipped when resuming from the latest stored `raised_at` timestamp.

## Changes

- Use the exact latest `raised_at` value for the alerts API `from_time` filter instead of advancing it by one second (the API semantics are “on or after”, so the previous offset could miss alerts still at the same second).
- Remove the unused `_from_time_after` helper and its tests.
