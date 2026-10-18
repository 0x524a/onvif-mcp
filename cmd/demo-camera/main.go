// Command demo-camera runs a virtual ONVIF camera for the zero-hardware demo.
//
// It listens on 127.0.0.1 at a fixed port with fixed, publicly documented demo
// credentials that match testdata/demo.json. Those credentials protect nothing
// but a simulator bound to the loopback interface; they are not secrets and
// must not be reused anywhere. The password is never printed.
//
// It runs as its own process so that nothing it writes can reach the stdout of
// a stdio MCP server, which carries only JSON-RPC. Its startup banner is
// discarded and one status line goes to stderr.
//
// The camera comes from onvif-go's server package (server.New, server.Config,
// Server.Start, Server.Addr).
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0x524a/onvif-go/server"
)

// Fixed demo values; keep in step with testdata/demo.json.
const (
	defaultPort = 18080
	demoUser    = "demo"
	demoPass    = "demo-pass-1234"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("demo-camera", flag.ContinueOnError)
	fs.SetOutput(stderr)
	port := fs.Int("port", defaultPort, "loopback port to listen on; testdata/demo.json expects the default")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ready := make(chan struct{})
	cfg := server.DefaultConfig()
	cfg.Host = "127.0.0.1"
	cfg.Port = *port
	cfg.Username = demoUser
	cfg.Password = demoPass
	cfg.SupportPTZ = true
	cfg.SupportImaging = true
	cfg.SupportEvents = false
	cfg.Output = io.Discard
	cfg.Ready = ready

	srv, err := server.New(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "demo-camera: create virtual camera: %v\n", err)
		return 1
	}
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()

	select {
	case <-ready:
		_, _ = fmt.Fprintf(stderr, "demo-camera: virtual camera ready at http://%s%s/device_service (demo credentials are in testdata/demo.json)\n",
			srv.Addr(), cfg.BasePath)
	case err := <-done:
		_, _ = fmt.Fprintf(stderr, "demo-camera: virtual camera did not start: %v\n", err)
		return 1
	case <-time.After(10 * time.Second):
		_, _ = fmt.Fprintln(stderr, "demo-camera: virtual camera not ready after 10s")
		return 1
	}

	if err := <-done; err != nil && ctx.Err() == nil {
		_, _ = fmt.Fprintf(stderr, "demo-camera: %v\n", err)
		return 1
	}
	return 0
}
