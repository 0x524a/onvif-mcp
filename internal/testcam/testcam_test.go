package testcam

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	onvif "github.com/0x524a/onvif-go"
	"github.com/0x524a/onvif-go/server"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
)

// newClient returns an initialized client for cam.
func newClient(t *testing.T, cam *Cam) *onvif.Client {
	t.Helper()
	c, err := onvif.NewClient(cam.Endpoint(),
		onvif.WithCredentials(cam.Username(), cam.Password()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return c
}

func TestStartServesInitializeAndProfiles(t *testing.T) {
	cam := Start(t)

	c, err := onvif.NewClient(cam.Endpoint(),
		onvif.WithCredentials(cam.Username(), cam.Password()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()
	if err := c.Initialize(ctx); err != nil {
		t.Fatalf("Initialize against virtual camera: %v", err)
	}
	profiles, err := c.GetProfiles(ctx)
	if err != nil {
		t.Fatalf("GetProfiles: %v", err)
	}
	if len(profiles) == 0 {
		t.Fatal("virtual camera returned no profiles")
	}
	if cam.ProfileToken() == "" || cam.PresetToken() == "" {
		t.Error("harness must expose a profile token and a preset token")
	}
	if cam.Server() == nil {
		t.Error("Server() must expose the underlying server")
	}
}

func TestTwoCamerasGetDistinctPorts(t *testing.T) {
	a, b := Start(t), Start(t)
	if a.Endpoint() == b.Endpoint() {
		t.Fatalf("both cameras bound the same endpoint: %s", a.Endpoint())
	}
}

func TestWrongPasswordIsRejected(t *testing.T) {
	cam := Start(t)
	c, err := onvif.NewClient(cam.Endpoint(),
		onvif.WithCredentials(cam.Username(), cam.Password()+"-wrong"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Initialize(context.Background()); err == nil {
		t.Fatal("Initialize succeeded with a wrong password; auth path is not enforced")
	}
}

func TestWrongUsernameIsRejected(t *testing.T) {
	cam := Start(t)
	c, err := onvif.NewClient(cam.Endpoint(),
		onvif.WithCredentials("nobody", cam.Password()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Initialize(context.Background()); err == nil {
		t.Fatal("Initialize succeeded with a wrong username")
	}
}

func TestStopClosesListener(t *testing.T) {
	cam := Start(t)
	addr := cam.addr

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("camera not accepting before Stop: %v", err)
	}
	_ = conn.Close()

	if err := cam.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Under heavy parallel load the kernel may hand the freed ephemeral port
	// to an unrelated process, so "nothing accepts" is too strong. What must
	// hold is that this camera (identified by its per-camera credential) no
	// longer answers.
	c, err := onvif.NewClient(cam.Endpoint(),
		onvif.WithCredentials(cam.Username(), cam.Password()),
		onvif.WithTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Initialize(context.Background()); err == nil {
		t.Fatal("camera still answers with its own credentials after Stop")
	}
	// Second Stop (and the t.Cleanup one) must be harmless.
	if err := cam.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

func TestStartIgnoresForeignListeners(t *testing.T) {
	// Occupy a port with a foreign listener. Because the camera binds port 0
	// and reads the address back, it must not care.
	foreign, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("foreign listen: %v", err)
	}
	defer func() { _ = foreign.Close() }()

	cam := Start(t)
	if cam.addr == foreign.Addr().String() {
		t.Fatalf("camera reported the foreign listener's address %s", cam.addr)
	}
	newClient(t, cam) // proves the camera itself answers
}

func TestPresetTokenIsMovable(t *testing.T) {
	cam := Start(t)
	c := newClient(t, cam)
	presets, err := c.GetPresets(context.Background(), cam.ProfileToken())
	if err != nil {
		t.Fatalf("GetPresets: %v", err)
	}
	var found bool
	for _, p := range presets {
		if p.Token == cam.PresetToken() {
			found = true
		}
	}
	if !found {
		t.Fatalf("PresetToken %q not among served presets", cam.PresetToken())
	}
	if cam.PTZPosition() != (server.PTZPosition{}) {
		t.Fatalf("initial position should be zero, got %+v", cam.PTZPosition())
	}
	if err := c.GotoPreset(context.Background(), cam.ProfileToken(), cam.PresetToken(), nil); err != nil {
		t.Fatalf("GotoPreset: %v", err)
	}
	if got := cam.PTZPosition(); got == (server.PTZPosition{}) {
		t.Fatalf("preset did not move the camera away from origin: %+v", got)
	}
}

func TestGetStreamURI(t *testing.T) {
	cam := Start(t)
	uri, err := newClient(t, cam).GetStreamURI(context.Background(), cam.ProfileToken())
	if err != nil {
		t.Fatalf("GetStreamURI: %v", err)
	}
	if uri == nil || uri.URI == "" {
		t.Fatalf("empty stream URI: %+v", uri)
	}
}

func TestGetPresetsAndStatus(t *testing.T) {
	cam := Start(t)
	c := newClient(t, cam)
	ctx := context.Background()
	presets, err := c.GetPresets(ctx, cam.ProfileToken())
	if err != nil || len(presets) == 0 {
		t.Fatalf("GetPresets: %v (%d presets)", err, len(presets))
	}
	st, err := c.GetStatus(ctx, cam.ProfileToken())
	if err != nil || st == nil {
		t.Fatalf("GetStatus: %v", err)
	}
}

func TestGetImagingSettings(t *testing.T) {
	cam := Start(t)
	c := newClient(t, cam)
	s, err := c.GetImagingSettings(context.Background(), cam.VideoSourceToken())
	if err != nil || s == nil {
		t.Fatalf("GetImagingSettings: %v", err)
	}
}

func TestGotoPresetUnknownTokenErrorType(t *testing.T) {
	cam := Start(t)
	c := newClient(t, cam)
	err := c.GotoPreset(context.Background(), cam.ProfileToken(), "no-such-preset", nil)
	if err == nil {
		t.Fatal("GotoPreset with unknown token succeeded")
	}
	var oe *onvif.ONVIFError
	asONVIF := errors.As(err, &oe)
	isSentinel := errors.Is(err, onvif.ErrPresetNotFound)
	te := mcperr.FromError(err, "cam", "goto_preset")
	t.Logf("unknown preset: err=%v (%T) errors.As(*ONVIFError)=%v errors.Is(ErrPresetNotFound)=%v mcperr=%s",
		err, err, asONVIF, isSentinel, te.Code)
	// Characterization, not endorsement: as of v1.2.0 the SOAP fault is
	// flattened into plain text by the client, so it is neither *ONVIFError nor
	// ErrPresetNotFound and mcperr.FromError currently classes it "internal"
	// rather than "not_found". Recorded here so the gap stays visible; the
	// mapping fix belongs in mcperr, not in this harness.
	if !strings.Contains(err.Error(), "preset not found") {
		t.Errorf("fault text no longer names the missing preset: %v", err)
	}
}

func TestPTZPositionIsRaceFree(t *testing.T) {
	cam := Start(t)
	c := newClient(t, cam)
	if err := c.GotoPreset(context.Background(), cam.ProfileToken(), cam.PresetToken(), nil); err != nil {
		t.Fatalf("GotoPreset: %v", err)
	}
	// Read while the settle timer is pending and after; run under -race.
	for i := 0; i < 3; i++ {
		_ = cam.PTZPosition()
	}
}
