// Command onvif-mcp serves ONVIF camera tools over the Model Context Protocol.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcpserver"
	"github.com/0x524a/onvif-mcp/internal/registry"
	"github.com/0x524a/onvif-mcp/internal/safety"
	"github.com/0x524a/onvif-mcp/internal/stdio"
	"github.com/0x524a/onvif-mcp/internal/tools"
)

func main() {
	ctx, stop := notifyWithGrace(context.Background(), shutdownGrace, os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// shutdownGrace is how long after the first SIGINT/SIGTERM a further signal is
// held instead of terminating the process. Inside it a stop that was already
// dispatched (ptz.stop) or a relative move in flight is not aborted by an
// impatient double signal; after it, default signal handling is restored, so a
// further signal ends a shutdown that is stuck.
const shutdownGrace = 5 * time.Second

// notifyWithGrace is signal.NotifyContext with that grace rule. The returned
// context is cancelled by the first signal in sigs. Further signals within grace
// are consumed and ignored. When grace has passed, default handling is restored
// (signal.Reset), so the next signal terminates the process. The returned stop
// function releases the handler and cancels the context.
//
// signal.NotifyContext cannot do this: its stop runs only after run returns, so a
// second signal during shutdown is swallowed for as long as shutdown takes.
func notifyWithGrace(parent context.Context, grace time.Duration, sigs ...os.Signal) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, sigs...)
	done := make(chan struct{})
	var once sync.Once
	go func() {
		defer signal.Stop(ch)
		select {
		case <-ch:
		case <-done:
			return
		}
		cancel()
		timer := time.NewTimer(grace)
		defer timer.Stop()
		for {
			select {
			case <-ch: // held: a stop in flight must not be aborted
			case <-timer.C:
				signal.Reset(sigs...)
				return
			case <-done:
				return
			}
		}
	}()
	return ctx, func() {
		once.Do(func() { close(done) })
		cancel()
	}
}

// run is main without the process-level side effects. Exit codes: 0 clean,
// 1 runtime or configuration failure, 2 usage error.
//
// stdout is the JSON-RPC channel once the server starts, so nothing but the
// SDK writes to it after that point. The only other thing ever written to
// stdout is the -version string, and only because the server is not started in
// that case. Every log line goes to stderr.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("onvif-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to the camera config file (required)")
	enableControl := fs.Bool("enable-control", false,
		"permit state-changing tools; each camera must also opt in via its config entry")
	snapshotMax := fs.Int("snapshot-max-bytes", tools.DefaultSnapshotMaxBytes,
		fmt.Sprintf("largest image camera.snapshot returns, in raw bytes (%d to %d); a larger snapshot is refused, not cut",
			tools.MinSnapshotMaxBytes, tools.MaxSnapshotMaxBytes))
	showVersion := fs.Bool("version", false, "print the version to stdout and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		_, _ = fmt.Fprintln(stdout, mcpserver.Version())
		return 0
	}

	if err := tools.CheckSnapshotMaxBytes(*snapshotMax); err != nil {
		_, _ = fmt.Fprintln(stderr, "onvif-mcp: -"+err.Error())
		return 2
	}

	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *cfgPath == "" {
		log.Error("missing required flag: -config")
		_, _ = fmt.Fprintln(stderr, "usage: onvif-mcp -config <path> [-enable-control] [-snapshot-max-bytes N]   (the config file must be mode 600; see the README)")
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("load config", "error", err)
		return 1
	}
	cfg.ControlEnabled = *enableControl

	reg := registry.New(cfg)
	for _, s := range reg.List() {
		log.Info("camera", "id", s.ID, "control_allowed", s.Control)
	}
	// The audit trail goes to the same stderr logger: stdout is JSON-RPC.
	policy := safety.NewPolicy(safety.PolicyOptions{
		ControlEnabled: cfg.ControlEnabled,
		Cameras:        reg,
		Log:            log,
	})
	log.Info("starting", "control_enabled", cfg.ControlEnabled, "write_tools_registered", policy.WriteRegistered(),
		"snapshot_max_bytes", *snapshotMax, "transport", "stdio")

	// ctx is also the base context of every tool call, so a signal aborts
	// in-flight camera I/O instead of waiting for it to time out.
	srv := mcpserver.New(reg, log, policy, mcpserver.WithBaseContext(ctx), mcpserver.WithSnapshotMaxBytes(*snapshotMax))
	tr := stdio.NewTransport(stdin, stdout, stdio.MaxLineBytes, log)
	err = srv.Run(ctx, tr)
	if err != nil && !errors.Is(err, context.Canceled) && !isStdinClosed(err) {
		log.Error("server stopped", "error", err)
		return 1
	}
	log.Info("server stopped")
	return 0
}

// isStdinClosed reports whether err is just the client closing stdin, which is
// how an MCP client ends a stdio session. With a request in flight the SDK
// reports it as "server is closing: EOF" (jsonrpc2.ErrServerClosing joined
// with the read error as text), which errors.Is cannot see through, so the
// text suffix is checked too.
func isStdinClosed(err error) bool {
	return errors.Is(err, io.EOF) || strings.HasSuffix(err.Error(), ": EOF")
}
