package testcam

import (
	"context"
	"net"
	"testing"
	"time"

	onvif "github.com/0x524a/onvif-go"
)

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
	if conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("port still accepting connections after Stop")
	}
	// Second Stop (and the t.Cleanup one) must be harmless.
	if err := cam.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}
