# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). The release workflow publishes the section
matching the pushed tag as the GitHub Release notes, so every tag needs a non-empty section.

## [Unreleased]

### Added

- `ptz.move_relative` (write, gated): nudge a PTZ camera by a small relative amount in the ONVIF
  generic translation space, with the space URI set explicitly on each vector. Each axis is capped at
  0.25 per call by the server; larger values are refused, not clamped, with an `invalid_argument`
  that names the field, the range, the source and a corrected call. Dry run by default, rate limited
  per device (shared with `ptz.goto_preset`), sent once and never retried, audited with the typed
  numbers sent. Relative moves do not consult the camera's reported limits.
- `ptz.stop` (halt, gated): stop pan, tilt and zoom on a profile, then read the status and report
  `confirmed_idle` or `sent_unconfirmed`; a stop that cannot be delivered is an error. It has no dry
  run, is never rate limited, does not need the audit log, and runs detached from the request and
  from shutdown. Bursts are bounded per device (two rounds in flight, profile tokens validated against
  the camera's own list). Stop is per profile.
- A third risk class, `RiskHalt`, in `internal/safety`, with `Policy.EvaluateHalt`, `HaltInput` and
  `HaltAnnotations`; a `NonIdempotent` registration option for writes that compound; a typed
  `WithMotion` audit option.
- The `onvif://server/policy` resource names the new tools, lists `halt_tools`, and says `ptz.stop` has
  no dry run and is not rate limited.
- Shutdown: a second SIGINT or SIGTERM inside 5 seconds of the first is held so it cannot abort a
  dispatched stop or a move in flight; a signal after that ends the process at once.
- An opt-in `hardware` test for a relative nudge pair and `ptz.stop` (`ONVIF_MCP_HW_NUDGE`); it has
  not been run against hardware.
- Tests that pin the go-sdk v1.7.0 handler-context and shutdown behaviour this design relies on.

### Changed

- With control on, `tools/list` now has thirteen tools (was eleven). With control off it is unchanged.
- The server reports version `v0.2.0` from source. Nothing is tagged or released yet: the release waits
  for the Streamable HTTP work.

### Not included

Continuous and absolute PTZ moves, a speed parameter, a cumulative travel budget for relative moves,
and verification on physical cameras. A looping model can still issue up to 30 capped steps a minute
per device.

## [0.1.0]

First release: a Model Context Protocol server (Go, stdio transport) that exposes ONVIF IP camera
inspection and guarded PTZ control as typed tools for an LLM agent.

### Added

- Eleven tools, ten of them read-only: `camera.list`, `camera.discover`, `camera.describe`,
  `media.profiles`, `media.stream_uri`, `stream.inspect` (RTSP OPTIONS and DESCRIBE: codecs, tracks,
  best-effort resolution), `camera.snapshot` (one JPEG or PNG inline, capped by
  `-snapshot-max-bytes`, default 1 MiB), `imaging.settings`, `ptz.status`, `ptz.presets`, and
  `ptz.goto_preset`, the only tool that changes a camera.
- The `onvif://server/policy` resource, which describes the current mode, the gated write tool and
  each camera's grant.
- Read-only by default: a real move needs `-enable-control` and a camera that opts in with
  `"control": true`; with control off, `ptz.goto_preset` is not in `tools/list`. Writes default to a dry
  run, are rate limited per device (one per 2 seconds), are sent once and never retried, and every
  attempt is audited to stderr.
- Credentials come from the mode-600 config file or `ONVIF_MCP_<ID>_PASSWORD`, never from tool
  arguments, results, logs or errors.
- Camera-supplied addresses are treated as hostile: service, stream and snapshot hosts must match
  the configured endpoint unless `trust_advertised_hosts` is set, and credentials are never sent to
  another host.
- Errors are a typed envelope (`code`, `retryable`, `message`, `hint`) instead of raw SOAP.
- `make demo` runs a virtual ONVIF camera (onvif-go's server package) on 127.0.0.1:18080 together
  with the server, so the tools can be tried without hardware.
- An opt-in `hardware` build-tag test tier for real cameras (`make hardware`); CI never runs it.
- `-version` prints the version and exits; release binaries report the tag they were built from.
- Release process: static cross-builds for linux, darwin and windows on amd64 and arm64, a
  `SHA256SUMS` file and build provenance attestations (see `RELEASING.md`).

### Not included

ONVIF events, continuous, relative or absolute PTZ, imaging or device writes, video serving, any
transport but stdio, and verification on physical cameras.

[Unreleased]: https://github.com/0x524a/onvif-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/0x524a/onvif-mcp/releases/tag/v0.1.0
