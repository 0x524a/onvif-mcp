package registry

import (
	"testing"

	"github.com/0x524a/onvif-mcp/internal/config"
)

func attestCfg(cams map[string][2]bool) *config.Config {
	cfg := &config.Config{Cameras: map[string]*config.Camera{}}
	for id, v := range cams {
		cfg.Cameras[id] = &config.Camera{ID: id, Endpoint: "http://192.0.2.10/" + id, Control: v[0], PTZHonoursTimeout: v[1]}
	}
	return cfg
}

func TestHonoursTimeoutIsPerCameraAndNeedsControl(t *testing.T) {
	r := New(attestCfg(map[string][2]bool{
		"attested":  {true, true},
		"plain":     {true, false},
		"no-grant":  {false, true}, // config.Load refuses this; the registry must not trust it either
		"read-only": {false, false},
	}))
	want := map[string]bool{"attested": true, "plain": false, "no-grant": false, "read-only": false}
	for id, w := range want {
		e, err := r.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		if got := e.HonoursTimeout(); got != w {
			t.Errorf("%s: HonoursTimeout = %v, want %v", id, got, w)
		}
	}
	if !r.AnyHonoursTimeout() {
		t.Error("AnyHonoursTimeout must be true when one granted camera attests")
	}
}

func TestAnyHonoursTimeoutIsFalseWithoutAGrantedAttestation(t *testing.T) {
	for name, cams := range map[string]map[string][2]bool{
		"none attests":          {"a": {true, false}, "b": {false, false}},
		"attested, not granted": {"a": {false, true}},
		"empty":                 {},
	} {
		if New(attestCfg(cams)).AnyHonoursTimeout() {
			t.Errorf("%s: AnyHonoursTimeout = true", name)
		}
	}
	var nilReg *Registry
	if nilReg.AnyHonoursTimeout() {
		t.Error("a nil registry attests nothing")
	}
}
