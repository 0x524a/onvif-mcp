package config

import (
	"strings"
	"testing"
)

func TestTrustAdvertisedHostsParsesAndDefaultsFalse(t *testing.T) {
	body := `{"cameras":{
	  "nat":{"endpoint":"192.0.2.10","password":"trustpass1","trust_advertised_hosts":true},
	  "plain":{"endpoint":"192.0.2.11","password":"trustpass2"}}}`
	cfg, err := Load(writeBody(t, body, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Cameras["nat"].TrustAdvertisedHosts {
		t.Error("trust_advertised_hosts:true was not read")
	}
	if cfg.Cameras["plain"].TrustAdvertisedHosts {
		t.Error("trust_advertised_hosts must default to false")
	}
}

func TestTrustAdvertisedHostsRejectsWrongTypeAndTypos(t *testing.T) {
	for name, body := range map[string]string{
		"string":   `{"cameras":{"a":{"endpoint":"192.0.2.10","password":"trustpass3","trust_advertised_hosts":"yes"}}}`,
		"typo":     `{"cameras":{"a":{"endpoint":"192.0.2.10","password":"trustpass3","trust_advertised_host":true}}}`,
		"wrongcap": `{"cameras":{"a":{"endpoint":"192.0.2.10","password":"trustpass3","Trust_Advertised_Hosts_X":true}}}`,
	} {
		_, err := Load(writeBody(t, body, 0o600))
		if err == nil {
			t.Errorf("%s: must be rejected", name)
			continue
		}
		if strings.Contains(err.Error(), "trustpass3") {
			t.Errorf("%s: error leaks the password: %v", name, err)
		}
	}
}
