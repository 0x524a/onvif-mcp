# onvif-mcp

A Model Context Protocol (MCP) server, written in Go, that exposes ONVIF IP camera
control as typed, safe tools an LLM agent can call.

## Status

v0.1 is in development. The tool surface below is filled in as each phase lands.

## Install

```bash
go install github.com/0x524a/onvif-mcp/cmd/onvif-mcp@latest
```

Requires Go 1.25 or newer. The command is not published until the first release.

## Configure

Cameras are declared in a JSON config file addressed by operator-chosen IDs. Credentials
live in the config file or the environment, never in tool arguments. Each camera must opt
in to control (`"control": true`), and control tools stay disabled unless the server is
started with `-enable-control`.

A documentation-only example is in [testdata/cameras.example.json](testdata/cameras.example.json),
using the reserved address `192.0.2.10` and `REPLACE_ME` credentials. Copy it, edit it, and
restrict its permissions:

```bash
cp testdata/cameras.example.json cameras.json
chmod 600 cameras.json
```

The server refuses to start if the config file is readable by group or other, because it
holds credentials. Git does not preserve the owner-only mode, so a fresh clone or copy
needs the `chmod` above.

## Run

```bash
onvif-mcp -config cameras.json
```

| Flag | Meaning |
|------|---------|
| `-config PATH` | Camera config file. Required. |
| `-enable-control` | Permit state-changing tools (each camera must also opt in). |
| `-version` | Print the version to stdout and exit without starting the server. |

The server speaks MCP over stdio: stdout carries only JSON-RPC, and all logging goes to
stderr. Exit codes: 0 on a clean shutdown (stdin closed, SIGINT or SIGTERM), 1 for a
configuration or runtime failure (including a config file with loose permissions), 2 for a
usage error such as an unknown flag or a missing `-config`.

## Tools

| Tool | Purpose | Status |
|------|---------|--------|
| _filled in as phases land_ | | |

## Scope / what this does not do

onvif-mcp deliberately exposes a small surface. It does **not**:

- Subscribe to or pull ONVIF events. The client library supports PullPoint, but the
  virtual camera used for testing implements no events service, so it cannot be
  covered without hardware.
- Perform continuous, relative, or absolute PTZ movement. Only `ptz.goto_preset`
  moves a camera, because a preset is a bounded target the device itself stored.
- Change imaging settings, reboot a device, manage users, or alter network
  configuration.
- Serve video. It reports stream URIs and inspects stream metadata; it never
  proxies or transcodes media.
- Discover and then drive a camera automatically. Discovery returns candidates
  only; a human must add a camera to the config before it is addressable.
- Verify advertised capabilities. `camera.describe` reports what a device claims,
  labelled as advertised rather than confirmed.
- Fix quirks of the MCP SDK it is built on. A few JSON-RPC errors from go-sdk
  v1.7.0 carry code `0` (for example `tools/list` before initialisation); they are
  passed through as the SDK emits them. On stdio, inbound lines over 4 MiB and
  lines that are not valid JSON-RPC 2.0 are answered with a `-32600` or `-32700`
  error and dropped, and the session continues.

## Licence

MIT. See [LICENSE](LICENSE).
