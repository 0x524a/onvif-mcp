package config

import (
	"strings"
	"testing"
)

func TestPermissionErrorNamesTheRemedy(t *testing.T) {
	p := writeBody(t, one("a", "h", ""), 0o644)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "chmod 600 "+p) {
		t.Errorf("error = %v, want it to say chmod 600 %s", err, p)
	}
}

func TestTypeErrorNamesTheCameraAndField(t *testing.T) {
	err := loadErr(t, `{"cameras":{"first":{"endpoint":"h"},"a":{"endpoint":"h","control":"yes"}}}`)
	if err == nil || !strings.Contains(err.Error(), `camera "a"`) || !strings.Contains(err.Error(), `"control"`) {
		t.Errorf("error = %v, want camera \"a\" and field \"control\"", err)
	}
	if err != nil && strings.Contains(err.Error(), "first") {
		t.Errorf("error blames the wrong camera: %v", err)
	}
}

func TestUnknownFieldNamesTheCamera(t *testing.T) {
	err := loadErr(t, `{"cameras":{"first":{"endpoint":"h"},"lobby":{"endpoint":"h","contorl":true}}}`)
	if err == nil || !strings.Contains(err.Error(), `camera "lobby"`) || !strings.Contains(err.Error(), "contorl") {
		t.Errorf("error = %v, want camera \"lobby\" and the field", err)
	}
	if err != nil && strings.Contains(err.Error(), "first") {
		t.Errorf("error blames the wrong camera: %v", err)
	}
}

func TestEverySyntaxErrorGivesAByteOffset(t *testing.T) {
	for name, body := range map[string]string{ //nolint:gosec // test fixtures
		"trailing comma": `{"cameras":{"a":{"endpoint":"h",}}}`,
		"truncated":      `{"cameras":{"a":{"endpoint":"h"`,
		"bad token":      `{"cameras":{"a":{"endpoint":h}}}`,
		"empty":          ``,
	} {
		err := loadErr(t, body)
		if err == nil || !strings.Contains(err.Error(), "at byte ") {
			t.Errorf("%s: error = %v, want a byte offset", name, err)
		}
	}
}
