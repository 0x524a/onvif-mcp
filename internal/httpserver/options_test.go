package httpserver

import (
	"strings"
	"testing"
)

const defaultSnap = 1 << 20

func httpFlags() Flags {
	//nolint:gosec // G101: "Tokens" is a file path flag, not a credential
	return Flags{
		Transport: "http", Tokens: "/tmp/tokens.json", SnapshotMaxBytes: defaultSnap, DefaultSnapshotMaxBytes: defaultSnap,
		Explicit: map[string]bool{"transport": true, "http-tokens": true},
	}
}

func with(f Flags, mut func(*Flags)) Flags {
	ex := map[string]bool{}
	for k, v := range f.Explicit {
		ex[k] = v
	}
	f.Explicit = ex
	mut(&f)
	return f
}

func setExplicit(f *Flags, names ...string) {
	for _, n := range names {
		f.Explicit[n] = true
	}
}

func TestValidateMatrix(t *testing.T) {
	tlsOn := func(f *Flags) {
		f.TLSCert, f.TLSKey = "c.pem", "k.pem"
		setExplicit(f, "tls-cert", "tls-key")
	}
	remote := func(listen string) func(*Flags) {
		return func(f *Flags) {
			f.Listen, f.AllowRemote, f.AllowedHosts = listen, true, "cams.example.net"
			tlsOn(f)
			setExplicit(f, "listen", "http-allow-remote", "http-allowed-hosts")
		}
	}
	cases := []struct {
		name    string
		f       Flags
		wantErr string // substring naming the flag; "" means ok
	}{
		{"stdio defaults", Flags{Explicit: map[string]bool{}, SnapshotMaxBytes: defaultSnap, DefaultSnapshotMaxBytes: defaultSnap}, ""},
		{"stdio explicit", Flags{Transport: "stdio", Explicit: map[string]bool{"transport": true}}, ""},
		{"bad transport", Flags{Transport: "sse", Explicit: map[string]bool{"transport": true}}, "-transport"},
		{"stdio with listen", Flags{Listen: "127.0.0.1:1", Explicit: map[string]bool{"listen": true}}, "-listen"},
		{"stdio with tokens", Flags{Tokens: "x", Explicit: map[string]bool{"http-tokens": true}}, "-http-tokens"},
		{"stdio with tls", Flags{TLSCert: "x", Explicit: map[string]bool{"tls-cert": true}}, "-tls-cert"},
		{"stdio with allow-remote", Flags{AllowRemote: true, Explicit: map[string]bool{"http-allow-remote": true}}, "-http-allow-remote"},
		{"http ok", httpFlags(), ""},
		{"http without tokens", with(httpFlags(), func(f *Flags) { f.Tokens = "" }), "-http-tokens"},
		{"http with enable-control", with(httpFlags(), func(f *Flags) { f.EnableControl = true }), "write tools are not offered over HTTP"},
		{"http with big snapshot", with(httpFlags(), func(f *Flags) { f.SnapshotMaxBytes = defaultSnap + 1 }), "-snapshot-max-bytes"},
		{"http with smaller snapshot", with(httpFlags(), func(f *Flags) { f.SnapshotMaxBytes = 4096 }), ""},
		{"new-token alone", Flags{NewToken: "ops", Explicit: map[string]bool{"new-token": true}}, ""},
		{"new-token with version", Flags{NewToken: "ops", Explicit: map[string]bool{"new-token": true, "version": true}}, ""},
		{"new-token with config", Flags{NewToken: "ops", Explicit: map[string]bool{"new-token": true, "config": true}}, "-new-token"},
		{"new-token with transport", Flags{NewToken: "ops", Explicit: map[string]bool{"new-token": true, "transport": true}}, "-new-token"},
		{"new-token bad id", Flags{NewToken: "Ops!", Explicit: map[string]bool{"new-token": true}}, "-new-token"},
		{"remote without allow-remote", with(httpFlags(), func(f *Flags) { f.Listen = "192.0.2.10:1"; setExplicit(f, "listen") }), "-http-allow-remote"},
		{"allow-remote without tls", with(httpFlags(), func(f *Flags) {
			f.Listen, f.AllowRemote, f.AllowedHosts = "192.0.2.10:1", true, "a.example"
			setExplicit(f, "listen", "http-allow-remote", "http-allowed-hosts")
		}), "-tls-cert"},
		{"tls without allowed hosts", with(httpFlags(), func(f *Flags) {
			f.Listen, f.AllowRemote = "192.0.2.10:1", true
			tlsOn(f)
			setExplicit(f, "listen", "http-allow-remote")
		}), "-http-allowed-hosts"},
		{"cert without key", with(httpFlags(), func(f *Flags) { f.TLSCert = "c"; setExplicit(f, "tls-cert") }), "-tls-key"},
		{"key without cert", with(httpFlags(), func(f *Flags) { f.TLSKey = "k"; setExplicit(f, "tls-key") }), "-tls-cert"},
		{"remote fully specified", with(httpFlags(), remote("192.0.2.10:8808")), ""},
		{"wildcard :port", with(httpFlags(), func(f *Flags) { f.Listen = ":8808"; setExplicit(f, "listen") }), "-http-allow-remote"},
		{"0.0.0.0", with(httpFlags(), func(f *Flags) { f.Listen = "0.0.0.0:1"; setExplicit(f, "listen") }), "-http-allow-remote"},
		{"[::]", with(httpFlags(), func(f *Flags) { f.Listen = "[::]:1"; setExplicit(f, "listen") }), "-http-allow-remote"},
		{"wildcard fully specified", with(httpFlags(), remote("0.0.0.0:8808")), ""},
		{"hostname refused", with(httpFlags(), func(f *Flags) { f.Listen = "example.com:1"; setExplicit(f, "listen") }), "-listen"},
		{"localhost", with(httpFlags(), func(f *Flags) { f.Listen = "localhost:1"; setExplicit(f, "listen") }), ""},
		{"loopback port 0", with(httpFlags(), func(f *Flags) { f.Listen = "127.0.0.1:0"; setExplicit(f, "listen") }), ""},
		{"ipv6 loopback", with(httpFlags(), func(f *Flags) { f.Listen = "[::1]:1"; setExplicit(f, "listen") }), ""},
		{"mapped loopback", with(httpFlags(), func(f *Flags) { f.Listen = "[::ffff:127.0.0.1]:1"; setExplicit(f, "listen") }), ""},
		{"ipv6 zone", with(httpFlags(), func(f *Flags) { f.Listen = "[fe80::1%eth0]:1"; setExplicit(f, "listen") }), "-listen"},
		{"bad port", with(httpFlags(), func(f *Flags) { f.Listen = "127.0.0.1:99999"; setExplicit(f, "listen") }), "-listen"},
		{"non-numeric port", with(httpFlags(), func(f *Flags) { f.Listen = "127.0.0.1:http"; setExplicit(f, "listen") }), "-listen"},
		{"no port", with(httpFlags(), func(f *Flags) { f.Listen = "127.0.0.1"; setExplicit(f, "listen") }), "-listen"},
		{"empty listen explicit", with(httpFlags(), func(f *Flags) { f.Listen = ""; setExplicit(f, "listen") }), "-listen"},
		{"allowed hosts with port", with(httpFlags(), func(f *Flags) { f.AllowedHosts = "a.example:8808"; setExplicit(f, "http-allowed-hosts") }), "-http-allowed-hosts"},
		{"allowed hosts trailing dot", with(httpFlags(), func(f *Flags) { f.AllowedHosts = "a.example."; setExplicit(f, "http-allowed-hosts") }), "-http-allowed-hosts"},
		{"allowed hosts wildcard", with(httpFlags(), func(f *Flags) { f.AllowedHosts = "*.example"; setExplicit(f, "http-allowed-hosts") }), "-http-allowed-hosts"},
		{"allowed hosts empty element", with(httpFlags(), func(f *Flags) { f.AllowedHosts = "a.example,,b.example"; setExplicit(f, "http-allowed-hosts") }), "-http-allowed-hosts"},
		{"allowed hosts on loopback ok", with(httpFlags(), func(f *Flags) { f.AllowedHosts = "Cams.Example,[::1]"; setExplicit(f, "http-allowed-hosts") }), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(tc.f)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want an error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not name %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateResolvesTheBind(t *testing.T) {
	r, err := Validate(httpFlags())
	if err != nil {
		t.Fatal(err)
	}
	if r.Listen != "127.0.0.1:8808" || !r.Loopback || r.TLS {
		t.Errorf("defaults resolved to %+v", r)
	}
	for _, h := range []string{"localhost", "127.0.0.1", "::1"} {
		if !r.AllowedHost(h) {
			t.Errorf("loopback bind must allow Host %q", h)
		}
	}
	r, _ = Validate(with(httpFlags(), func(f *Flags) { f.Listen = "localhost:9"; setExplicit(f, "listen") }))
	if r.Listen != "127.0.0.1:9" {
		t.Errorf("localhost must bind as 127.0.0.1, got %q", r.Listen)
	}
	r, err = Validate(with(httpFlags(), func(f *Flags) {
		f.Listen, f.AllowRemote, f.AllowedHosts, f.TLSCert, f.TLSKey = "192.0.2.10:1", true, "Cams.Example", "c", "k"
		setExplicit(f, "listen", "http-allow-remote", "http-allowed-hosts", "tls-cert", "tls-key")
	}))
	if err != nil {
		t.Fatal(err)
	}
	if r.Loopback || !r.TLS || !r.AllowedHost("cams.example") || r.AllowedHost("localhost") || r.AllowedHost("127.0.0.1") {
		t.Errorf("remote bind must not add loopback defaults: %+v", r)
	}
}

func TestValidateErrorsDoNotEchoFileContents(t *testing.T) {
	f := with(httpFlags(), func(f *Flags) { f.TLSCert = "/secret/path/cert-sentinel.pem"; setExplicit(f, "tls-cert") })
	if _, err := Validate(f); err == nil || strings.Contains(err.Error(), "sentinel") {
		t.Errorf("err = %v", err)
	}
}
