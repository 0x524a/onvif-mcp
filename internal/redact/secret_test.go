package redact

import (
	"fmt"
	"strings"
	"testing"
)

// isolateSecrets runs with an empty registry and restores the previous one.
func isolateSecrets(t *testing.T) {
	t.Helper()
	secretsMu.Lock()
	oldReg, oldForms, oldRep := registered, formSet, replacer
	registered, formSet, replacer = map[string]struct{}{}, map[string]struct{}{}, nil
	secretsMu.Unlock()
	t.Cleanup(func() {
		secretsMu.Lock()
		registered, formSet, replacer = oldReg, oldForms, oldRep
		secretsMu.Unlock()
	})
}

func TestRegisteredSecretsReplacedLongestFirst(t *testing.T) {
	isolateSecrets(t)
	RegisterSecret("abc")
	RegisterSecret("abcdef")
	if got := Scrub("x abcdef y"); strings.Contains(got, "def") {
		t.Errorf("shorter secret exposed remainder of longer one: %q", got)
	}
}

func TestRegisterSecretCap(t *testing.T) {
	isolateSecrets(t)
	for i := 0; i < maxSecrets; i++ {
		if !RegisterSecret(fmt.Sprintf("secret-%04d", i)) {
			t.Fatalf("registration %d refused below cap", i)
		}
	}
	if !RegisterSecret("secret-0000") {
		t.Error("re-registering an existing secret must report true at the cap")
	}
	if RegisterSecret("one-too-many") {
		t.Error("registration beyond the cap must return false")
	}
	if got := Scrub("one-too-many"); got != "one-too-many" {
		t.Errorf("refused secret was registered anyway: %q", got)
	}
	if got := Scrub("secret-0255"); got != "REDACTED" {
		t.Errorf("last accepted secret not scrubbed: %q", got)
	}
	if RegisterSecret("ab") {
		t.Error("too-short secret must return false")
	}
}

func TestJWTAndBearerKeysRedacted(t *testing.T) {
	for _, in := range []string{
		"jwt=eyJhbGciOi.payload.sig",
		"bearer=abcdef123",
		`{"jwt":"eyJhbGciOi.payload.sig"}`,
		`{"bearer":"abcdef123"}`,
		"a=1&jwt=eyJhbGciOi.payload.sig",
	} {
		got := Scrub(in)
		if strings.Contains(got, "eyJ") || strings.Contains(got, "abcdef123") {
			t.Errorf("not redacted: %q -> %q", in, got)
		}
	}
}
