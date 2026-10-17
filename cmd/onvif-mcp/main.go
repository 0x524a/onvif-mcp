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
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/config"
	"github.com/0x524a/onvif-mcp/internal/mcpserver"
	"github.com/0x524a/onvif-mcp/internal/registry"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run is main without the process-level side effects. Exit codes: 0 clean,
// 1 runtime or configuration failure, 2 usage error.
//
// stdout is the JSON-RPC channel once the server starts, so nothing but the
// SDK writes to it after that point. The only other thing ever written to
// stdout is the -version string, and only because the server is not started in
// that case. Every log line goes to stderr.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("onvif-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to the camera config file (required)")
	enableControl := fs.Bool("enable-control", false,
		"permit state-changing tools; each camera must also opt in via its config entry")
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

	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *cfgPath == "" {
		log.Error("missing required flag: -config")
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
	log.Info("starting", "control_enabled", *enableControl, "transport", "stdio")

	err = mcpserver.New(reg, log).Run(ctx, &mcp.StdioTransport{})
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Error("server stopped", "error", err)
		return 1
	}
	log.Info("server stopped")
	return 0
}
