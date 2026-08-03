# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Types of changes: Added, Changed, Deprecated, Removed, Fixed, Security

## [0.1.3] - 2026-08-03

### Added

- Added a singleton daemon control channel for safe stop, reload, and rollback requests.
- Added baseline, applied, and pending configuration snapshots for declarative reconciliation and interrupted-apply recovery.
- Added persistent DHCPv6 client identity and broader regression coverage for lifecycle, parser, DHCP, DNS, state, WiFi, and rollback behavior.

### Changed

- Reload and restart now remove obsolete managed state before applying the desired configuration.
- Rollback protection is enabled by default, starts its confirmation timer only after a successful apply, and can be disabled explicitly with `--no-rollback`.
- Native DHCP now falls back to the first available external client unless a client is selected explicitly.
- Init scripts use non-blocking service supervision, and install targets honor `DESTDIR`, custom prefixes, and init directories.
- The systemd installer no longer stops or masks the existing network stack unless `NIC_DISABLE_SYSTEM_SERVICES=1` is requested.

### Fixed

- Fixed daemon shutdown leaving native or external DHCP clients running.
- Fixed incomplete rollback of addresses, routes, routing rules, link properties, master relationships, virtual links, WiFi, and DNS state.
- Fixed stale configuration accumulating across reloads and interrupted applies.
- Fixed inverse command generation for abbreviated iproute2 commands, VLAN creation, and master assignments.
- Fixed DHCP one-shot deadlocks, ignored link and route failures, renewal transition ordering, cancellation latency, and DHCPv6 identity checks.
- Fixed external DHCP fallback detection and process ownership tracking.
- Fixed WiFi teardown selecting the wrong interface and failing to restore IWD profiles.
- Fixed quoted comments, malformed quoting, include cycles, numeric sort overflow, argument counts, and value validation in the configuration parser.
- Fixed staged installs writing configuration or registering services on the host system.

### Security

- WiFi passwords are no longer passed in helper command-line arguments or verbose command logs.
- WiFi configuration and runtime credential files are restricted to mode `0600`, with safe escaping and IWD filename encoding.
- Daemon, watcher, DHCP, and WiFi process signaling now validates process start times to prevent PID-reuse mistakes.
- Interface references are validated before they can be used in runtime file paths.

## [0.1.2] - 2026-03-29

### Fixed

- Restart/reload handling

## [0.1.1] - 2026-03-25

### Fixed

- Bugfixes for dhcp, colors, error handling

## [0.1.0] - 2026-03-25

### Added

- First release
