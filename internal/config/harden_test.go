package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func loadErr(t *testing.T, body string) error {
	t.Helper()
	_, err := Load(writeBody(t, body, 0o600))
	return err
}

func TestDirectoryPathIsNotRegular(t *testing.T) {
	if _, err := Load(t.TempDir()); !errors.Is(err, ErrNotRegular) {
		t.Errorf("got %v, want ErrNotRegular", err)
	}
}

func TestTimeoutBounds(t *testing.T) {
	for _, v := range []string{"-5", "301", "9999999999999", "-9999999999999"} {
		body := fmt.Sprintf(`{"cameras":{"cam1":{"endpoint":"h","timeout_seconds":%s}}}`, v)
		err := loadErr(t, body)
		if err == nil || !strings.Contains(err.Error(), "cam1") {
			t.Errorf("timeout %s: got %v, want error naming cam1", v, err)
		}
	}
	for _, v := range []string{"0", "1", "300"} {
		body := fmt.Sprintf(`{"cameras":{"cam1":{"endpoint":"h","timeout_seconds":%s}}}`, v)
		if err := loadErr(t, body); err != nil {
			t.Errorf("timeout %s must be accepted: %v", v, err)
		}
	}
}

func TestUnknownFieldsRejectedWithoutValues(t *testing.T) {
	const pw = "typo-secret-Kk91" //nolint:gosec // test fixture
	bodies := map[string]string{
		"camera field":   `{"cameras":{"a":{"endpoint":"h","pasword":"` + pw + `"}}}`,
		"top-level":      `{"extra":"` + pw + `","cameras":{"a":{"endpoint":"h"}}}`,
		"control typo":   `{"cameras":{"a":{"endpoint":"h","contrl":true}}}`,
		"timeout typo":   `{"cameras":{"a":{"endpoint":"h","timout_seconds":3}}}`,
		"id-like config": `{"cameras":{"a":{"endpoint":"h","ID":"` + pw + `"}}}`,
	}
	for name, b := range bodies {
		err := loadErr(t, b)
		if err == nil {
			t.Errorf("%s: unknown field must be rejected", name)
			continue
		}
		if strings.Contains(err.Error(), pw) {
			t.Errorf("%s: error echoes a value: %v", name, err)
		}
		if !strings.Contains(err.Error(), "unknown field") {
			t.Errorf("%s: error should say unknown field: %v", name, err)
		}
	}
	err := loadErr(t, bodies["camera field"])
	if err == nil || !strings.Contains(err.Error(), "pasword") {
		t.Errorf("error should name the field: %v", err)
	}
}

func TestTrailingDataRejected(t *testing.T) {
	if err := loadErr(t, one("a", "h", "")+` {"cameras":{}}`); err == nil {
		t.Error("trailing JSON value must be rejected")
	}
}

func TestDuplicateCameraIDsRejected(t *testing.T) {
	body := `{"cameras":{"dup":{"endpoint":"h1"},"ok":{"endpoint":"h3"},"dup":{"endpoint":"h2"}}}`
	err := loadErr(t, body)
	if err == nil || !strings.Contains(err.Error(), "dup") {
		t.Errorf("got %v, want duplicate error naming dup", err)
	}
}

func TestEmptyEnvOverrideIsAnError(t *testing.T) {
	t.Setenv("ONVIF_MCP_A_PASSWORD", "")
	err := loadErr(t, one("a", "h", "filepass-Hh12"))
	if err == nil || !strings.Contains(err.Error(), "ONVIF_MCP_A_PASSWORD") {
		t.Errorf("got %v, want error naming the variable", err)
	}
}

func TestEndpointSchemes(t *testing.T) {
	for _, ep := range []string{"file:///etc/passwd", "ftp://x", "rtsp://h/s", "FILE://x", "://x"} {
		err := loadErr(t, one("cam", ep, ""))
		if err == nil {
			t.Errorf("endpoint %q must be rejected", ep)
		} else if strings.Contains(err.Error(), ep) {
			t.Errorf("error echoes endpoint %q: %v", ep, err)
		}
	}
	for _, ep := range []string{"h", "192.0.2.1:8080", "http://h", "HTTPS://h:443/onvif", "[2001:db8::1]:80"} {
		if err := loadErr(t, one("cam", ep, "")); err != nil {
			t.Errorf("endpoint %q must be accepted: %v", ep, err)
		}
	}
}

func TestUnparseableEndpointNeverEchoed(t *testing.T) {
	for _, ep := range []string{"http://h:notaport/x", "http://%zz/", "http://[::1/", "http://h:99999999/"} {
		err := loadErr(t, one("cam", ep, ""))
		if err == nil {
			t.Errorf("endpoint %q must be rejected", ep)
			continue
		}
		if strings.Contains(err.Error(), ep) || strings.Contains(err.Error(), "notaport") || strings.Contains(err.Error(), "%zz") {
			t.Errorf("error echoes endpoint: %v", err)
		}
		if !strings.Contains(err.Error(), "cam") {
			t.Errorf("error should name camera: %v", err)
		}
	}
}

func TestRejectsDotIDs(t *testing.T) {
	for _, id := range []string{".", ".."} {
		if err := loadErr(t, one(id, "h", "")); err == nil {
			t.Errorf("ID %q must be rejected", id)
		}
	}
}

func TestStructuralGuards(t *testing.T) {
	for name, body := range map[string]string{
		"null camera":    `{"cameras":{"a":null}}`,
		"empty cameras":  `{"cameras":{}}`,
		"null cameras":   `{"cameras":null}`,
		"blank endpoint": `{"cameras":{"a":{"endpoint":"   "}}}`,
	} {
		if err := loadErr(t, body); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

func TestOversizeFileRejected(t *testing.T) {
	pad := strings.Repeat(" ", maxConfigBytes)
	if err := loadErr(t, one("a", "h", "")+pad); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("got %v, want too large", err)
	}
	// Exactly at the limit still loads.
	body := one("a", "h", "")
	body += strings.Repeat(" ", maxConfigBytes-len(body))
	if err := loadErr(t, body); err != nil {
		t.Errorf("file at the limit must load: %v", err)
	}
}

func TestDotAndUnderscoreIDsCollide(t *testing.T) {
	err := loadErr(t, `{"cameras":{"a.b":{"endpoint":"h1"},"a_b":{"endpoint":"h2"}}}`)
	if err == nil || !strings.Contains(err.Error(), "ONVIF_MCP_A_B_PASSWORD") {
		t.Errorf("got %v, want collision naming the variable", err)
	}
}

func TestPermissionErrorStillWorksForFIFOFix(t *testing.T) {
	// Regression guard: O_NONBLOCK open must not break the permission check.
	p := write(t, 0o640)
	if _, err := Load(p); !errors.Is(err, ErrConfigPermissions) {
		t.Errorf("got %v", err)
	}
	_ = os.Remove(p)
}
