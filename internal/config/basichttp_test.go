package config

import (
	"strings"
	"testing"
)

func TestAllowBasicOverHTTPParsesAndDefaultsFalse(t *testing.T) {
	body := `{"cameras":{
	  "old":{"endpoint":"192.0.2.10","password":"basicpass1","allow_basic_over_http":true},
	  "plain":{"endpoint":"192.0.2.11","password":"basicpass2"}}}`
	cfg, err := Load(writeBody(t, body, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Cameras["old"].AllowBasicOverHTTP {
		t.Error("allow_basic_over_http:true was not read")
	}
	if cfg.Cameras["plain"].AllowBasicOverHTTP {
		t.Error("allow_basic_over_http must default to false")
	}
}

func TestAllowBasicOverHTTPRejectsWrongType(t *testing.T) {
	_, err := Load(writeBody(t, `{"cameras":{"a":{"endpoint":"192.0.2.10","password":"basicpass3","allow_basic_over_http":"yes"}}}`, 0o600))
	if err == nil {
		t.Fatal("a string value must be rejected")
	}
	if strings.Contains(err.Error(), "basicpass3") {
		t.Errorf("error leaks the password: %v", err)
	}
}
