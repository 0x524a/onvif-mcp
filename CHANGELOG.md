# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). The release workflow publishes the section
matching the pushed tag as the GitHub Release notes, so every tag needs a non-empty section.

## [Unreleased]

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
