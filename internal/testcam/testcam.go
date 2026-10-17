// Package testcam runs onvif-go's virtual camera as an in-process test fixture.
//
// It exists to work around upstream onvif-go issue #63: at the pinned version
// (v1.1.4) server.Start binds a fixed port with no ephemeral option, blocks
// with no readiness signal, and prints banners to stdout. Once that issue is
// resolved this package should shrink to a thin wrapper.
//
// Stdout noise: v1.1.4 writes its startup and shutdown banners with fmt.Printf
// straight to os.Stdout and offers no way to redirect them. This package does
// not swap os.Stdout (that would race across parallel tests). The noise is
// harmless in tests; the MCP JSON-RPC channel on stdout exists only in the real
// binary, which never imports this package.
package testcam

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/0x524a/onvif-go/server"
)

const (
	bindAttempts    = 5
	readyTimeout    = 3 * time.Second
	shutdownTimeout = 10 * time.Second
)

// Cam is a running virtual camera bound to a free port.
type Cam struct {
	srv          *server.Server
	cfg          *server.Config
	addr         string
	profileToken string
	presetToken  string

	cancel   context.CancelFunc
	done     chan error
	stopOnce sync.Once
	stopErr  error
}

// Start boots a virtual camera and registers cleanup with t. A bind failure
// (the port freed by freePort being taken before the server binds it) is
// retried with a new port up to five times.
func Start(t *testing.T) *Cam {
	t.Helper()

	var lastErr error
	for attempt := 1; attempt <= bindAttempts; attempt++ {
		cam, err := tryStart()
		if err == nil {
			t.Cleanup(func() {
				if err := cam.Stop(); err != nil {
					t.Errorf("testcam cleanup: %v", err)
				}
			})
			return cam
		}
		lastErr = err
		t.Logf("testcam: start attempt %d/%d failed: %v", attempt, bindAttempts, err)
	}
	t.Fatalf("testcam: virtual camera failed to start after %d attempts: %v", bindAttempts, lastErr)
	return nil
}

func tryStart() (*Cam, error) {
	port, err := freePort()
	if err != nil {
		return nil, fmt.Errorf("freePort: %w", err)
	}

	cfg := server.DefaultConfig()
	cfg.Host = "127.0.0.1"
	cfg.Port = port
	cfg.Username = "operator"
	cfg.Password = "testpass"
	cfg.SupportPTZ = true
	cfg.SupportImaging = true

	if len(cfg.Profiles) == 0 {
		return nil, errors.New("DefaultConfig returned no profiles; adjust the harness")
	}
	// Guarantee the first profile is PTZ-capable and has a preset, so later
	// phases have a bounded target to move to.
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
	if len(p.PTZ.Presets) == 0 {
		p.PTZ.Presets = []server.Preset{{Token: "preset1", Name: "Preset 1"}}
	}

	srv, err := server.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("server.New: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()

	cam := &Cam{
		srv: srv, cfg: cfg,
		addr:         fmt.Sprintf("127.0.0.1:%d", port),
		profileToken: p.Token,
		presetToken:  p.PTZ.Presets[0].Token,
		cancel:       cancel,
		done:         done,
	}

	if err := cam.waitReady(readyTimeout); err != nil {
		// Start may have returned already (bind failure); Stop drains it.
		_ = cam.Stop()
		return nil, err
	}
	return cam, nil
}

// waitReady polls until the address accepts connections, failing early if the
// server goroutine exits (for example "address already in use").
func (c *Cam) waitReady(within time.Duration) error {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		select {
		case err := <-c.done:
			c.done <- err // keep it for Stop
			return fmt.Errorf("server exited before becoming ready: %w", err)
		default:
		}
		conn, err := net.DialTimeout("tcp", c.addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			// A foreign listener could answer the dial while our server
			// failed to bind; make sure Start has not already returned.
			select {
			case err := <-c.done:
				c.done <- err
				return fmt.Errorf("server exited before becoming ready: %w", err)
			case <-time.After(30 * time.Millisecond):
			}
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("no listener on %s after %v", c.addr, within)
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
func (c *Cam) ProfileToken() string { return c.profileToken }

// PresetToken returns a preset that exists on the first profile.
func (c *Cam) PresetToken() string { return c.presetToken }

// Server returns the underlying virtual camera.
func (c *Cam) Server() *server.Server { return c.srv }

// freePort asks the kernel for an unused port, then releases it. There is a
// small race between release and the server binding it, which Start covers by
// retrying; unavoidable until issue #63 allows Port 0 with address read-back.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}
