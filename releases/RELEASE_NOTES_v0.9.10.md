# Release v0.9.10

## Summary

Adds Central firewall configuration import/export support, including asynchronous transaction polling and documentation for downloading completed exports.

## Changes

- Add firewall configuration export and import helper methods under `central.firewalls.config`.
- Add data classes for export transaction references, pre-signed import upload URLs, import completion requests, and firewall-config transactions.
- Add `wait_for_firewall_config_transaction`, with a 15 second default polling interval and optional `on_update` / `on_complete` callbacks.
- Document full and partial firewall configuration export flows, import upload completion, transaction polling, and export download URL handling in the README.
- Parse transaction requests where Central returns `request.query` as `null`.
