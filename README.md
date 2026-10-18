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
The same flag decides whether `stream.inspect` may probe a stream on another host; it never
makes onvif-mcp send credentials there (see "Stream credentials" below).

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

Write tools are rate limited per device: one movement per 2 seconds, burst 1. The budget is
keyed by the camera's endpoint (case, scheme, default port and a trailing slash are
ignored), so two config entries that point at the same endpoint share one budget. These
are code defaults (`safety.PolicyOptions`), and v0.1 has no flag or config key to change
them; `onvif://server/policy` reports the values in force.

The server speaks MCP over stdio: stdout carries only JSON-RPC, and all logging goes to
stderr. Exit codes: 0 on a clean shutdown (stdin closed, SIGINT or SIGTERM), 1 for a
configuration or runtime failure (including a config file with loose permissions), 2 for a
usage error such as an unknown flag or a missing `-config`.

## Tools

| Tool | Purpose | Kind |
|------|---------|------|
| `camera.list` | List configured cameras; optionally probe reachability | read-only |
| `camera.discover` | WS-Discovery probe that returns candidates to add to the config | read-only |
| `camera.describe` | Device information and advertised services | read-only |
| `media.profiles` | Media profiles and whether each has PTZ | read-only |
| `media.stream_uri` | Stream URI for a profile, credentials removed | read-only |
| `stream.inspect` | Open a profile's RTSP stream and report codecs, tracks and best-effort resolution | read-only, open-world |
| `imaging.settings` | Current imaging settings of a video source | read-only |
| `ptz.status` | Current PTZ position and movement state | read-only |
| `ptz.presets` | Stored presets and reported movement limits | read-only |
| `ptz.goto_preset` | Move a camera to a stored preset | write, gated (see below) |

### `ptz.goto_preset`

The only tool that changes a camera. It takes `camera`, `profile` (a token from
`media.profiles` with `has_ptz` true), `preset` (a token from `ptz.presets`) and `dry_run`.
Three independent gates stand between an agent and a moving motor:

1. **The operator starts the server with `-enable-control`.** Without it the tool is not
   registered: it does not appear in `tools/list` and cannot be called. The
   `onvif://server/policy` resource still names it, says why it is gated and what an
   operator must do.
2. **The camera opts in** with `"control": true` in its config entry. A camera that has not
   opted in refuses with `blocked_by_policy`, for dry runs as well.
3. **The caller passes `dry_run: false`.** `dry_run` defaults to true. A dry run does the
   same validation a real call does (camera known, profile exists and carries PTZ, preset
   exists) and reports the preset's stored target position and the camera's reported
   movement limits, but never sends the move command. It says exactly what to send to
   move.

A real call is rate limited (see above), sends the move command once and never retries it.
A call that fails before anything is sent (a mistyped token, an unreachable camera, a
cancellation) gives its budget back and is audited as not executed. When the call
succeeds, the camera returned HTTP success; the library does not parse the reply, so that
does not prove the camera accepted the command, and it may still be moving. `ptz.status`
shows where it is. If a real call times out or faults after the command was
sent, the camera may or may not have moved: the error says so, is not marked retryable, and
the agent should check `ptz.status` before trying again. The same holds for any other
failure after the send, such as a reply that is not SOAP. Dry runs are not rate limited,
but each costs several round trips to the camera (connect, profiles, presets, limits), so
an agent looping on them still loads it. Validation as a whole is held to twice the
camera's `timeout_seconds`. Every attempt, dry or real, and
every refusal is written to stderr with the tool, camera, dry-run state, whether it executed,
the outcome and the preset token. Arguments and credentials are never logged.

v0.1 performs no clamping. The target is a preset the camera stored itself, so it is
reachable by construction; `reported_limits` is informational and is never compared with
the target. When absolute or relative moves are added, a camera that reports no limits will
fail closed rather than fall back to a guessed range.

To enable it for one camera:

```bash
# in cameras.json, on the PTZ camera only:  "control": true
onvif-mcp -config cameras.json -enable-control
```

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
- `stream.inspect` runs the RTSP OPTIONS and DESCRIBE handshake against a profile's stream and
  reports `reachable`, `describe_ok`, `latency_ms` and up to 32 tracks (type, codec, and for
  H.264 and H.265 video the width and height). Resolution is parsed from the stream's own
  parameter sets and is best-effort; a track without it has no width or height. The result
  names the stream as scheme, host, port and path only. `timeout_seconds` defaults to 5 and is
  clamped to 10; it is independent of the camera's own `timeout_seconds` config setting. A
  stream that answers with an RTSP redirect is not followed (`device_fault`). Credentials never
  appear in its input or output (see below).
- `camera.discover` blocks for its whole probe window (3 s by default, 10 s at most). The
  underlying library checks for cancellation only between packets, so a cancel or shutdown
  waits out the rest of the window. A host with no usable network interface fails with
  `unreachable`. Everything in a candidate is an unauthenticated claim by whatever answered;
  a device can also reuse a real camera's endpoint reference to overwrite its addresses, which
  is inherent to WS-Discovery. Candidates on a directly attached network are preferred when the
  list is capped.

### Stream credentials

The stream address comes from the camera, so a hostile or compromised camera could name any
host. `stream.inspect` therefore adds the camera's configured username and password to the
RTSP URL itself, inside the server process, and only under these rules:

- The address's host must be the host of the camera's configured ONVIF endpoint (the rule
  that guards advertised service addresses). The scheme must be `rtsp` or `rtsps` and any
  port 1 to 65535. Userinfo the camera put in the address is discarded.
- Any other host is refused as `device_fault` ("camera advertised a stream address on another
  host") and **nothing is probed**: no credentials, and no connection either, so the tool
  cannot be used to scan an internal network.
- A camera whose config sets `trust_advertised_hosts` is the one exception: its other-host
  streams are probed, **without credentials** (`authenticated` is false). Unspecified,
  multicast, broadcast and link-local addresses (including 169.254.169.254) and numeric host
  spellings are refused even then, and the same check is applied to the address a
  host name resolves to, before any connection is made.
- The probe's client may open one connection, to the single address of the URL (resolved
  once), and never follows an RTSP redirect: a 3xx from the stream is an error, so a stream
  cannot steer the credentials, or the probe, to another host or port.
- The credentialed URL is never returned, logged or placed in an error. It lives in an
  unprintable registry type that only this tool can reach, and every output passes the
  redactor.

## Scope / what this does not do

onvif-mcp deliberately exposes a small surface. It does **not**:

- Subscribe to or pull ONVIF events. The client library supports PullPoint, but the
  virtual camera used for testing implements no events service, so it cannot be
  covered without hardware.
- Perform continuous, relative, or absolute PTZ movement. Only `ptz.goto_preset`
  moves a camera, because a preset is a target the camera itself stored.
- Change imaging settings, reboot a device, manage users, or alter network
  configuration.
- Serve video. It reports stream URIs and inspects stream metadata; it never
  proxies, records or transcodes media, and `stream.inspect` fetches no frames.
- Stay inside the ONVIF service. `stream.inspect` is open-world: it connects to a stream
  endpoint, which is a separate service from the camera's ONVIF one. The camera's
  credentials leave the process only toward the camera's own host, and never toward
  another host; with `trust_advertised_hosts`, another host is probed without them.
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
