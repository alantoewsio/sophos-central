# Release v0.9.6

## Summary

Expands the Sophos Central alerts integration with single-alert fetch, POST search with automatic pagination, alert actions, richer list filtering, and supporting models.

## Changes

- Add `get_alert` to fetch one alert by ID (optional `fields`, tenant header).
- Add `search_alerts` for `POST /common/v1/alerts/search`, following `pageFromKey` until all pages are collected.
- Add `take_alert_action` for `POST /common/v1/alerts/{alertId}/actions` and `AlertActionResult` for 201 responses.
- Extend `get_alerts` query parameters: `group_key`, `from_time`, `to_time`, `sort`, `product`, `category`, `severity`, `ids`, `fields`.
- Export new symbols from `central.alerts`.
