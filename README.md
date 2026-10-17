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

Cameras are declared in a config file addressed by operator-chosen IDs. Credentials live
in the config file or the environment, never in tool arguments. Each camera must opt in to
control, and control tools stay disabled unless the server is started with
`--enable-control`.

## Run

```bash
onvif-mcp --config cameras.json
```

The server speaks MCP over stdio. All logging goes to stderr.

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

## Licence

MIT. See [LICENSE](LICENSE).
