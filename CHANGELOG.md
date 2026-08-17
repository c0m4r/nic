# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Types of changes: Added, Changed, Deprecated, Removed, Fixed, Security

## [0.1.6] - 2026-08-17

### Fixed

- IPv6 DAD running without active v6

## [0.1.5] - 2026-08-12

### Added

- Added the `dhcpv6 <iface> required` modifier, which restores the previous behavior of treating any DHCPv6 failure as fatal to the whole configuration.
- Added `dhcp4` and `dhcpv4` as aliases for `dhcp`, and `dhcp6` as an alias for `dhcpv6`. Spellings are normalized when parsed, so switching between them is not reported as a configuration change.

### Changed

- `dhcpv6` is now best-effort, following NetworkManager's `may-fail` model. A failed DHCPv6 lease is a warning when the interface is configured by another address family, and remains an error only when the interface is left with no address at all. Previously a single unreachable DHCPv6 server rolled back every interface on the host.

### Fixed

- Fixed baseline restore failing on hosts with a tunnel device such as `sit0`, which rejects every link-layer address change. Link addresses and MTUs are now only rewritten when they differ from the live value, so `start`, `stop`, and `restart` no longer abort before configuring anything.
- Fixed DHCPv6 aborting with `sendto: cannot assign requested address` when the solicit was sent from a link-local address still undergoing duplicate address detection. The client now waits for DAD to settle, reports a duplicate address instead of hanging, and retries transient send failures.

## [0.1.4] - 2026-08-12

### Fixed

- Various bugfixes and ehnacements

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
