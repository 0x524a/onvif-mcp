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

### Advertised service addresses and `trust_advertised_hosts`

A camera tells the server where its media, PTZ and imaging services live, and the server
sends authenticated requests there. A hostile or misconfigured camera could use that to
aim requests at an unrelated host. By default onvif-mcp therefore refuses any request whose
host differs from the host in the camera's configured `endpoint` (a different port on the
same host is fine, and loopback addresses are already rewritten to the configured host by
the client library). The tool then fails with `device_fault`: "camera advertised a service
address on another host".

For a camera behind NAT or with several addresses, set `"trust_advertised_hosts": true` on
that camera to turn the check off for it. The default is `false`. Hosts are compared as
written, so a camera configured by name that advertises its IP address needs the flag too.

A reply body over 8 MiB is rejected with `device_fault` ("camera response too large")
instead of being read into memory.

## Run

```bash
onvif-mcp -config cameras.json
```

| Flag | Meaning |
|------|---------|
| `-config PATH` | Camera config file. Required. |
| `-enable-control` | Permit state-changing tools (each camera must also opt in). |
| `-version` | Print the version to stdout and exit without starting the server. |

Write tools are rate limited per camera: one movement per 2 seconds, burst 1. These are
code defaults (`safety.PolicyOptions`), and v0.1 has no flag or config key to change them;
`onvif://server/policy` reports the values in force.

The server speaks MCP over stdio: stdout carries only JSON-RPC, and all logging goes to
stderr. Exit codes: 0 on a clean shutdown (stdin closed, SIGINT or SIGTERM), 1 for a
configuration or runtime failure (including a config file with loose permissions), 2 for a
usage error such as an unknown flag or a missing `-config`.

## Tools

| Tool | Purpose | Status |
|------|---------|--------|
| _filled in as phases land_ | | |

### Output limits and caveats

- Every string in a tool result is stripped of control and formatting characters, scrubbed
  of registered secrets, and clipped to 256 characters. Non-finite numbers a camera reports
  are treated as not reported.
- Lists are capped, and a capped result says so with `truncated: true` and a `total`:
  `media.profiles` 100, `ptz.presets` 256, `camera.describe` services 64,
  `camera.discover` candidates 64. A repeated profile or preset token keeps its first
  entry and is counted in `duplicates_dropped`.
- `media.stream_uri` removes userinfo, known secret query keys, registered passwords and the
  fragment. A secret embedded in the URI path cannot be detected and is not removed. A URI
  over 2048 characters is a `device_fault`.
- `camera.discover` blocks for its whole probe window (3 s by default, 10 s at most). The
  underlying library checks for cancellation only between packets, so a cancel or shutdown
  waits out the rest of the window. A host with no usable network interface fails with
  `unreachable`. Everything in a candidate is an unauthenticated claim by whatever answered;
  a device can also reuse a real camera's endpoint reference to overwrite its addresses, which
  is inherent to WS-Discovery. Candidates on a directly attached network are preferred when the
  list is capped.

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
