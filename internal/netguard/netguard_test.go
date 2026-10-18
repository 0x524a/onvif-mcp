package netguard

import "testing"

func TestNeverProbed(t *testing.T) {
	for h, want := range map[string]bool{
		"169.254.169.254": true, "0.0.0.0": true, "::": true, "224.0.0.1": true, "255.255.255.255": true,
		"fe80::1": true, "::ffff:169.254.169.254": true, "0x7f000001": true, "2130706433": true,
		"127.0.0.1": false, "10.0.0.5": false, "camera.local": false, "::1": false,
	} {
		if got := NeverProbed(h); got != want {
			t.Errorf("NeverProbed(%q) = %v, want %v", h, got, want)
		}
	}
}
