package config

import (
	"strings"
	"testing"
)

// ptz_honours_timeout is the operator's attestation that a camera ends a
// continuous move by itself when the ONVIF Timeout runs out. It defaults to false
// and is meaningless without control, so it is refused there rather than kept
// as a dormant claim.
func TestHonoursTimeoutDefaultsOff(t *testing.T) {
	cfg, err := Load(write(t, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	for id, c := range cfg.Cameras {
		if c.PTZHonoursTimeout {
			t.Errorf("%s: ptz_honours_timeout must default to false", id)
		}
	}
}

func TestHonoursTimeoutIsReadWithControl(t *testing.T) {
	body := `{"cameras":{"dome":{"endpoint":"http://192.0.2.10/onvif/device_service","control":true,"ptz_honours_timeout":true}}}`
	cfg, err := Load(writeBody(t, body, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Cameras["dome"].PTZHonoursTimeout {
		t.Error("ptz_honours_timeout true was not read")
	}
}

func TestHonoursTimeoutWithoutControlIsRefused(t *testing.T) {
	for name, entry := range map[string]string{
		"control omitted": `"ptz_honours_timeout":true`,
		"control false":   `"control":false,"ptz_honours_timeout":true`,
	} {
		body := `{"cameras":{"dome":{"endpoint":"http://192.0.2.10/onvif/device_service",` + entry + `}}}`
		_, err := Load(writeBody(t, body, 0o600))
		if err == nil {
			t.Fatalf("%s: a timeout attestation without control must be refused", name)
		}
		for _, want := range []string{`"dome"`, "ptz_honours_timeout", "control"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error %q lacks %q", name, err, want)
			}
		}
	}
}

func TestHonoursTimeoutMustBeABoolean(t *testing.T) {
	body := `{"cameras":{"dome":{"endpoint":"http://192.0.2.10/onvif/device_service","control":true,"ptz_honours_timeout":"yes"}}}`
	_, err := Load(writeBody(t, body, 0o600))
	if err == nil || !strings.Contains(err.Error(), "ptz_honours_timeout") || !strings.Contains(err.Error(), "wrong type") {
		t.Fatalf("err = %v", err)
	}
}
