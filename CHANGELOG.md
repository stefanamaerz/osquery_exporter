# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.1.0] - 2026-09-08

### Fixed
- Fixed version string output regression where release binaries printed local `main.Version` ("dev") instead of build-injected `version.Version` ([#54], [#52]).
- Refined Thrift reconnect logic to only reconnect on actual transport-level and protocol failures, preventing ordinary SQL failures and context cancellations from tearing down the shared connection ([#54], [#53]).

### Changed
- Performed a codebase simplification and cleanup audit to streamline architecture across multiple packages (collector, model, osquery, main, and tests) and improve connection resilience ([#49]).

## [v0.0.7] - 2026-08-28

### Added
- Added arm64 Debian package builds to release and build workflows ([#27]).
- Added `--version` command-line flag to print version information ([#39]).
- Added configurable query result caching with TTL to limit osquery load ([#40]).
- Added CUE schema for configuration validation and integration with CI ([#45]).

### Changed
- Pin Go toolchain version via `go.mod` and use `go-version-file` in GitHub Actions workflows ([#38]).
- Hardened graceful shutdown sequence to ensure in-flight scrapes complete and cancel safely ([#42]).
- Replaced MD5 with SHA-256 for internal metric and query identifiers ([#37]).
- Set HTTP request and header size limits on the metrics server as defense-in-depth ([#46]).

### Fixed
- Declared package dependency on `osquery` for the Debian package ([#26]).
- Validated socket path ownership, permissions, and structure before startup ([#43]).
- Validated configured SQL queries are read-only and fail fast on invalid syntax ([#44]).
- Fixed version pinning of `actions/download-artifact` action in the release workflow ([#48]).

## [v0.0.6] - 2026-08-24

### Changed
- Reverted packaging to dpkg-deb with correct package name `osquery-exporter` and included changelog ([#25]).

## [v0.0.5] - 2026-08-24

### Fixed
- Corrected Debian package name to `osquery-exporter` (replacing invalid underscores) ([#24]).

## [v0.0.4] - 2026-08-24

### Added
- Packaged default config and systemd unit in `.deb` release package ([#15]).
- Added CLI flag to disable Go runtime and process metrics ([#16]).
- Added load-test utility with realistic `--load-rps` throttling ([#19]).
- Added support for shared named queries via `queryref` and query execution deduplication ([#22]).

### Changed
- Switched `.deb` packaging approach to nFPM ([#23]).

### Fixed
- Fixed YAML structure in the introspection config example ([#14]).

## [v0.0.3] - 2026-08-22

### Added
- Added example configuration for osquery internal introspection metrics ([#12]).

### Changed
- Switched to the official `osquery-go` Thrift extension socket runner ([#7]).
- Added context-aware queries, Thrift auto-reconnect, and HTTP server timeouts ([#9]).

### Fixed
- Fixed metric registration correctness, failing fast on duplicates, and safely emitting metrics ([#10]).
- Added signal handling, graceful HTTP shutdown, fixed busy-waiting in `integration/waitForSocket`, and improved documentation/examples ([#11]).
- Fixed Thrift reconnect gating, metric validation correctness, and startup validation ([#13]).

## [v0.0.2] - 2026-08-22

### Changed
- Released an intermediate development tag (no explicit functional differences recorded).

## [v0.0.1] - 2026-08-22

### Added
- Initial release of `osquery_exporter`.
- Modernized Go toolchain (Go 1.27), updated dependencies, and added slog logging ([#1]).
- Added comprehensive unit and integration test suite ([#3]).
- Added GitHub Actions CI workflows for testing and `.deb` packaging ([#4]).
- Configured `.gitignore` for coverage outputs and set up Dependabot ([#5]).

[Unreleased]: https://github.com/stefanamaerz/osquery_exporter/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/stefanamaerz/osquery_exporter/compare/v0.0.7...v0.1.0
[v0.0.7]: https://github.com/stefanamaerz/osquery_exporter/compare/v0.0.6...v0.0.7
[v0.0.6]: https://github.com/stefanamaerz/osquery_exporter/compare/v0.0.5...v0.0.6
[v0.0.5]: https://github.com/stefanamaerz/osquery_exporter/compare/v0.0.4...v0.0.5
[v0.0.4]: https://github.com/stefanamaerz/osquery_exporter/compare/v0.0.3...v0.0.4
[v0.0.3]: https://github.com/stefanamaerz/osquery_exporter/compare/v0.0.2...v0.0.3
[v0.0.2]: https://github.com/stefanamaerz/osquery_exporter/compare/v0.0.1...v0.0.2
[v0.0.1]: https://github.com/stefanamaerz/osquery_exporter/releases/tag/v0.0.1

[#1]: https://github.com/stefanamaerz/osquery_exporter/pull/1
[#3]: https://github.com/stefanamaerz/osquery_exporter/pull/3
[#4]: https://github.com/stefanamaerz/osquery_exporter/pull/4
[#5]: https://github.com/stefanamaerz/osquery_exporter/pull/5
[#7]: https://github.com/stefanamaerz/osquery_exporter/pull/7
[#9]: https://github.com/stefanamaerz/osquery_exporter/pull/9
[#10]: https://github.com/stefanamaerz/osquery_exporter/pull/10
[#11]: https://github.com/stefanamaerz/osquery_exporter/pull/11
[#12]: https://github.com/stefanamaerz/osquery_exporter/pull/12
[#13]: https://github.com/stefanamaerz/osquery_exporter/pull/13
[#14]: https://github.com/stefanamaerz/osquery_exporter/pull/14
[#15]: https://github.com/stefanamaerz/osquery_exporter/pull/15
[#16]: https://github.com/stefanamaerz/osquery_exporter/pull/16
[#19]: https://github.com/stefanamaerz/osquery_exporter/pull/19
[#22]: https://github.com/stefanamaerz/osquery_exporter/pull/22
[#23]: https://github.com/stefanamaerz/osquery_exporter/pull/23
[#24]: https://github.com/stefanamaerz/osquery_exporter/pull/24
[#25]: https://github.com/stefanamaerz/osquery_exporter/pull/25
[#26]: https://github.com/stefanamaerz/osquery_exporter/pull/26
[#27]: https://github.com/stefanamaerz/osquery_exporter/pull/27
[#37]: https://github.com/stefanamaerz/osquery_exporter/pull/37
[#38]: https://github.com/stefanamaerz/osquery_exporter/pull/38
[#39]: https://github.com/stefanamaerz/osquery_exporter/pull/39
[#40]: https://github.com/stefanamaerz/osquery_exporter/pull/40
[#42]: https://github.com/stefanamaerz/osquery_exporter/pull/42
[#43]: https://github.com/stefanamaerz/osquery_exporter/pull/43
[#44]: https://github.com/stefanamaerz/osquery_exporter/pull/44
[#45]: https://github.com/stefanamaerz/osquery_exporter/pull/45
[#46]: https://github.com/stefanamaerz/osquery_exporter/pull/46
[#48]: https://github.com/stefanamaerz/osquery_exporter/pull/48
[#49]: https://github.com/stefanamaerz/osquery_exporter/pull/49
[#52]: https://github.com/stefanamaerz/osquery_exporter/pull/52
[#53]: https://github.com/stefanamaerz/osquery_exporter/pull/53
[#54]: https://github.com/stefanamaerz/osquery_exporter/pull/54
