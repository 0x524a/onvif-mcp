# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). The release workflow publishes the section
matching the pushed tag as the GitHub Release notes, so every tag needs a non-empty section.

## [Unreleased]

### Added

- `ptz.move_continuous` (stdio, gated): move at a velocity of at most 0.5 per axis, in the explicit
  ONVIF generic velocity space, for a required `duration_seconds` of 0.5 to 5; the call blocks and the
  server then stops the camera itself and reports `stop_status` and `stopped_by`. It is a dry run by
  default. The duration is sent as the camera's ONVIF `Timeout` (rounded up to the millisecond). The
  server's stop is sent from a deferred call on a context detached from the request, so it also
  follows a cancel, a shutdown signal, stdin closing, a panic or a failed send: up to 3 attempts 1 s
  apart within 8 s, then tri-state confirmation. A stop that cannot be delivered fails the call with
  `MOTION MAY CONTINUE on camera ...` and an error-level audit record.
- `ptz_honours_timeout` camera config key (default `false`, requires `"control": true`): the
  operator's attestation that the camera stops a continuous move by itself when the ONVIF `Timeout`
  runs out. `ptz.move_continuous` is registered only when at least one camera sets it and refuses,
  dry or real, any camera that does not. After SIGKILL, an OOM kill or power loss mid-move that
  `Timeout` is the only thing left that stops the camera, and the server cannot check the claim.
- A per-device budget of seconds of motion for `ptz.move_continuous` (5 s, one second regained per
  4 s), charged in full before each move is sent and never refunded.
- Opt-in hardware tests `TestHardwareTimeoutHonoured` (the attestation proof: moves with the
  fractional `Timeout`s the tool sends, `PT1.5S` and `PT0.5S`, and no stop must each end by
  themselves) and `TestHardwareContinuousMove`, behind the `hardware`
  build tag and `ONVIF_MCP_HW_CONTINUOUS=<camera-id>:<profile-token>`. Neither has been run.
- Audit records `motion started` and `motion stopped`, paired by a server-generated `motion_id`.

### Changed

- Every real write now holds a per-device lease for the whole call. A second real move on a camera
  that is busy (same endpoint, any id, any write tool) is refused with `blocked_by_policy`,
  `retry_after_seconds` and no rate token spent, where before two concurrent calls could both pass
  the gate. `ptz.stop` never takes the lease and is never blocked by it.
- `ptz.stop` first tells a `ptz.move_continuous` on the same camera to end (that move then sends its
  own stop too), and reports `interrupted_motion`. A stop that arrives while the move is still being
  validated cancels it before it is sent.
- The `onvif://server/policy` resource names `ptz.move_continuous` among the gated tools, reports
  `ptz_honours_timeout` per camera (always false over HTTP) and the
  `continuous_motion_budget_per_camera`.

- **Go 1.26 or newer is now required** (go.mod `go 1.26.0`), because rtspeek v1.0.0 and go-sdk v1.8.0 need it. Dependencies: rtspeek 0.2.0 to 1.0.0, go-sdk 1.7.0 to 1.8.0, gortsplib 5.5.0 to 5.6.6, mediacommon 2.9.3 to 2.9.5, and indirect updates. `stream.inspect` reads the codec name from the stream's rtpmap instead of gortsplib's deprecated `Format.Codec`.

### Verified

- `ptz.goto_preset` passed the gated hardware move on the Reolink TrackMix (one preset, no return preset).

## [0.2.1] - 2026-10-25

### Fixed

- `ptz.move_relative` failed on strict (gSOAP) cameras: onvif-go v1.2.0 wrote the `PanTilt` and `Zoom`
  children of the move vector outside the ONVIF schema namespace, and a Reolink TrackMix answered every
  move with `tag name namespace mismatch in element 'PanTilt'`. Fixed in onvif-go v1.2.1, which this
  release requires. The same fix covers `AbsoluteMove` and `ContinuousMove` in the library.

### Verified

- The `hardware` tier passed on a physical camera for the first time: the read matrix on five cameras
  (Axis, Reolink, three Bosch) and the relative nudge pair with `ptz.stop` on the Reolink TrackMix.
  Preset moves (`ptz.goto_preset`) have still not been run on hardware.

## [0.2.0] - 2026-10-23

Two gated PTZ tools over stdio and a read-only streamable HTTP transport. Not yet verified on a
physical camera: the `hardware` tier for `ptz.move_relative` and `ptz.stop` has not been run.

### Added

- HTTP hardening from review: JSON-RPC batch arrays are refused with 400 (one 64 KiB batch
  of `tools/list` calls could be expanded into a roughly 40 MB reply); the tool name in
  the HTTP audit line is truncated to 64 bytes; the policy resource reports
  `control_allowed` as false over HTTP; the TLS minimum-version test now genuinely
  exercises the server, and shutdown has tests for 503 + `Connection: close` while draining
  and for closing connections still open past the deadline.
- Streamable HTTP transport, read-only: `-transport http` with `-listen` (default
  `127.0.0.1:8808`), `-http-tokens`, `-http-allow-remote`, `-http-allowed-hosts`,
  `-tls-cert` and `-tls-key`. Stateless, JSON responses, HTTP/1.1 only. Authentication is
  mandatory: static bearer tokens held as SHA-256 digests in a mode-600 file, one uniform
  401 for every failure, constant-time comparison. `Host` is checked against an allowlist
  on every bind and any `Origin` header is refused. A non-loopback bind needs
  `-http-allow-remote`, in-process TLS (1.2 or newer) and allowed hosts. Bounded
  connections (total and per remote IP), timeouts, header and body sizes, requests in
  flight, tool calls in flight (total and per token) and per-call deadline; single-phase
  drain on shutdown with a second signal ending the process. Details and the limits table
  are in the README ("Serving over HTTP").
- `-new-token ID`: print a fresh 256-bit token and its token-file entry, then exit.
- Per-token `grant` list in the token file: `camera.snapshot`, `camera.discover` and
  `stream.inspect` are available over HTTP only to tokens granted them, and are hidden from
  `tools/list` otherwise.
- `make demo-http`: the virtual camera plus the HTTP server on loopback, read-only, with a
  throwaway token.
- Tool-call audit line on HTTP (`tool`, `caller`, `transport`, `outcome`) and an access log
  with the token id; tokens, digests and `Authorization` values are never logged.
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
- A golden for the `onvif://server/policy` resource, with control on and off.

### Fixed

- `ptz.stop` sends Stop even when the camera's profile list cannot be read for any reason (timeout,
  dropped connection, garbage reply); the profile read is best effort and gets half the attempt.
- `ptz.stop` no longer reports a stop as not sent when a round may already have dispatched it (caller
  context ended, round panicked, or a later attempt failed after an earlier one sent); the audit
  record follows. Round time is capped inside the halt budget.
- `ptz.stop` rounds are keyed by camera id as well as device, so cameras sharing an endpoint with
  different credentials never share a round.
- `ptz.move_relative` adds a hint on a SOAP fault about the explicit translation space; validation
  timeouts no longer mention a preset; the `ptz.stop` description no longer claims it stops motion
  started elsewhere.

### Changed

- **Behaviour change for embedders and tests, none for stdio users:** the write guard now
  fails closed on identity. `Policy.Evaluate` and `Policy.EvaluateHalt` take the request
  context and refuse (`caller_unidentified` / `caller_not_granted` in the audit trail,
  with one agent-facing message) unless it carries a caller with control; the check runs
  before the camera lookup, so it reveals nothing about camera ids. The stdio server
  supplies the operator explicitly. `mcpserver.New` without a caller source refuses
  `tools/call` and `resources/read`.
- The policy resource on HTTP reports `read-only` with no gated tools and no advice to pass
  `--enable-control`, identically for every caller.
- Handler panics in HTTP tool calls are converted to an internal tool error instead of
  ending the process.
- With control on, `tools/list` now has thirteen tools (was eleven). With control off it is unchanged.
- The server reports version `v0.2.0` from source.

### Not included

Continuous and absolute PTZ moves, a speed parameter, a cumulative travel budget for relative moves,
and verification on physical cameras. A looping model can still issue up to 30 capped steps a minute
per device.
Motion or any other state-changing tool over HTTP (write tools are stdio-only in this
release), OAuth or mTLS, browser clients, token or certificate hot-reload, and a per-token
camera allowlist.

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

[Unreleased]: https://github.com/0x524a/onvif-mcp/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/0x524a/onvif-mcp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/0x524a/onvif-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/0x524a/onvif-mcp/releases/tag/v0.1.0
