//go:build unix

package config

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFIFOConfigPathDoesNotHang(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo.json")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("mkfifo unavailable")
	}
	done := make(chan error, 1)
	go func() { _, err := Load(p); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("got %v, want ErrNotRegular", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Load hung on a FIFO")
	}
}
