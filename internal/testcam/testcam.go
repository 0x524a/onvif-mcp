// Package testcam runs onvif-go's virtual camera as an in-process test fixture.
//
// It targets onvif-go v1.2.0 (upstream issue #63 resolved there): the harness
// binds port 0, waits on server.Config.Ready, reads the bound address back from
// server.Server.Addr, and sends the startup banner to io.Discard through
// server.Config.Output. No port is ever pre-picked, so there is no race with
// other listeners and no retry loop.
package testcam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	onvif "github.com/0x524a/onvif-go"
	"github.com/0x524a/onvif-go/server"
)

const (
	readyTimeout    = 5 * time.Second
	shutdownTimeout = 10 * time.Second
	settleTimeout   = 10 * time.Second
	pollInterval    = 20 * time.Millisecond

	// movablePresetToken is appended only when the default config has no
	// usable preset.
	movablePresetToken = "testcam_preset"
)

// Cam is a running virtual camera bound to an OS-assigned port.
type Cam struct {
	srv         *server.Server
	cfg         *server.Config
	addr        string
	profile     string
	videoSource string
	preset      string

	cancel   context.CancelFunc
	done     chan error
	stopOnce sync.Once
	stopErr  error

	clientOnce sync.Once
	client     *onvif.Client
	clientErr  error
}

// Start boots a virtual camera and registers cleanup with t.
func Start(t *testing.T) *Cam {
	t.Helper()
	cam, err := start()
	if err != nil {
		t.Fatalf("testcam: %v", err)
	}
	t.Cleanup(func() {
		if err := cam.Stop(); err != nil {
			t.Errorf("testcam cleanup: %v", err)
		}
	})
	return cam
}

func start() (*Cam, error) {
	ready := make(chan struct{})

	cfg := server.DefaultConfig()
	cfg.Host = "127.0.0.1"
	cfg.Port = 0 // OS-assigned; the real address is read back via Server.Addr
	cfg.Username = "operator"
	cfg.Password = randomPassword()
	cfg.SupportPTZ = true
	cfg.SupportImaging = true
	cfg.Output = io.Discard
	cfg.Ready = ready

	if len(cfg.Profiles) == 0 {
		return nil, errors.New("DefaultConfig returned no profiles; adjust the harness")
	}
	// Guarantee the first profile is PTZ-capable.
	p := &cfg.Profiles[0]
	if p.PTZ == nil {
		p.PTZ = &server.PTZConfig{
			NodeToken:          "node0",
			PanRange:           server.Range{Min: -180, Max: 180},
			TiltRange:          server.Range{Min: -90, Max: 90},
			ZoomRange:          server.Range{Min: 0, Max: 1},
			SupportsContinuous: true,
			SupportsAbsolute:   true,
			SupportsRelative:   true,
		}
	}
	preset := pickMovablePreset(p.PTZ)

	srv, err := server.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("server.New: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()

	cam := &Cam{
		srv: srv, cfg: cfg,
		profile:     p.Token,
		videoSource: p.VideoSource.Token,
		preset:      preset,
		cancel:      cancel,
		done:        done,
	}

	select {
	case <-ready:
	case err := <-done:
		cancel()
		return nil, fmt.Errorf("server exited before becoming ready: %w", err)
	case <-time.After(readyTimeout):
		_ = cam.Stop()
		return nil, fmt.Errorf("server not ready within %v", readyTimeout)
	}
	cam.addr = srv.Addr()
	if cam.addr == "" {
		_ = cam.Stop()
		return nil, errors.New("server signalled ready but reported no address")
	}
	return cam, nil
}

// randomPassword gives every camera a distinct credential so a test can tell
// "this camera" from an unrelated process that was handed the same ephemeral
// port after this camera released it.
func randomPassword() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("testcam: crypto/rand: %v", err))
	}
	return "pw-" + hex.EncodeToString(b)
}

// pickMovablePreset returns the token of a preset whose position differs from
// the initial (zero) PTZ position, appending one if none exists.
func pickMovablePreset(ptz *server.PTZConfig) string {
	for _, pr := range ptz.Presets {
		if pr.Position != (server.PTZPosition{}) {
			return pr.Token
		}
	}
	ptz.Presets = append(ptz.Presets, server.Preset{
		Token:    movablePresetToken,
		Name:     "Testcam Movable",
		Position: server.PTZPosition{Pan: 10, Tilt: 5, Zoom: 0.5},
	})
	return movablePresetToken
}

// Stop shuts the camera down and waits for the server goroutine to return. It
// is idempotent and is also registered with t.Cleanup by Start.
func (c *Cam) Stop() error {
	c.stopOnce.Do(func() {
		c.cancel()
		select {
		case err := <-c.done:
			if err != nil {
				c.stopErr = fmt.Errorf("server returned: %w", err)
			}
		case <-time.After(shutdownTimeout):
			c.stopErr = fmt.Errorf("virtual camera goroutine did not exit within %v of cancel", shutdownTimeout)
		}
	})
	return c.stopErr
}

// Endpoint returns the device service URL.
func (c *Cam) Endpoint() string {
	return fmt.Sprintf("http://%s%s/device_service", c.addr, c.cfg.BasePath)
}

// Username returns the configured username.
func (c *Cam) Username() string { return c.cfg.Username }

// Password returns the configured password.
func (c *Cam) Password() string { return c.cfg.Password }

// ProfileToken returns the first profile's token (PTZ-capable).
func (c *Cam) ProfileToken() string { return c.profile }

// VideoSourceToken returns the first profile's video source token, as used by
// imaging calls.
func (c *Cam) VideoSourceToken() string { return c.videoSource }

// PresetToken returns a preset on the first profile whose position differs
// from the initial PTZ position, so GotoPreset observably moves the camera.
func (c *Cam) PresetToken() string { return c.preset }

// Server returns the underlying virtual camera.
//
// Caution: methods such as GetPTZState return pointers into live state that
// the server's settle timer mutates after a move, so reading those fields
// directly races. Use PTZPosition for a race-free read.
func (c *Cam) Server() *server.Server { return c.srv }

// PTZPosition returns the first profile's PTZ position once any move has
// settled. It reads over the wire (PTZ GetStatus), which the server serves
// under its own lock, so it never touches live state and is safe under -race.
// It panics if the camera cannot be queried or does not settle in time (a
// harness failure, not a product condition).
func (c *Cam) PTZPosition() server.PTZPosition {
	pos, err := c.ptzPosition()
	if err != nil {
		panic(fmt.Sprintf("testcam: PTZPosition: %v", err))
	}
	return pos
}

func (c *Cam) ptzPosition() (server.PTZPosition, error) {
	c.clientOnce.Do(func() {
		cl, err := onvif.NewClient(c.Endpoint(), onvif.WithCredentials(c.Username(), c.Password()))
		if err == nil {
			err = cl.Initialize(context.Background())
		}
		c.client, c.clientErr = cl, err
	})
	if c.clientErr != nil {
		return server.PTZPosition{}, c.clientErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), settleTimeout)
	defer cancel()
	for {
		st, err := c.client.GetStatus(ctx, c.profile)
		if err != nil {
			return server.PTZPosition{}, err
		}
		if st.MoveStatus == nil || (st.MoveStatus.PanTilt != "MOVING" && st.MoveStatus.Zoom != "MOVING") {
			var pos server.PTZPosition
			if st.Position != nil {
				if st.Position.PanTilt != nil {
					pos.Pan, pos.Tilt = st.Position.PanTilt.X, st.Position.PanTilt.Y
				}
				if st.Position.Zoom != nil {
					pos.Zoom = st.Position.Zoom.X
				}
			}
			return pos, nil
		}
		select {
		case <-ctx.Done():
			return server.PTZPosition{}, fmt.Errorf("PTZ still moving after %v", settleTimeout)
		case <-time.After(pollInterval):
		}
	}
}
