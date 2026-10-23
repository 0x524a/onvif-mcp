package safety

import "slices"

// optInTools are the read tools that reach beyond "read a configured camera's
// metadata", so a remote caller gets them only through an explicit per-token
// grant: camera.snapshot (live imagery), camera.discover (multicast and probing
// from the server host's LAN) and stream.inspect (server-originated RTSP
// connections). Stdio is unaffected: the operator has everything.
var optInTools = []string{"camera.discover", "camera.snapshot", "stream.inspect"}

// OptInTools returns the opt-in read tool names, sorted. The caller owns the slice.
func OptInTools() []string { return slices.Clone(optInTools) }

// IsOptInTool reports whether name is an opt-in read tool.
func IsOptInTool(name string) bool { return slices.Contains(optInTools, name) }
