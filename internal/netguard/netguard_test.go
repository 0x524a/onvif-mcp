package netguard

import "testing"

func TestNeverProbed(t *testing.T) {
	for h, want := range map[string]bool{
		"169.254.169.254": true, "0.0.0.0": true, "::": true, "224.0.0.1": true, "255.255.255.255": true,
		"fe80::1": true, "::ffff:169.254.169.254": true, "0x7f000001": true, "2130706433": true,
		"127.0.0.1": false, "10.0.0.5": false, "camera.local": false, "::1": false,
		// Tunnel and metadata spellings of never-probed addresses.
		"64:ff9b::a9fe:a9fe": true, "64:ff9b::169.254.169.254": true, "64:ff9b::7f00:1": false,
		"64:ff9b:1::a9fe:a9fe": true, "64:ff9b:1:0:0:a9fe:a9fe:0": true, "64:ff9b:1:a9fe:a9:fe00::": true,
		"2002:a9fe:a9fe::": true, "2002:a9fe:a9fe:1::5": true, "2002:7f00:1::": false,
		"::a9fe:a9fe": true, "::169.254.169.254": true, "::7f00:1": false, "::10.0.0.5": false,
		"fd00:ec2::254": true, "fd00:ec2::253": false, "100.100.100.200": true, "100.100.100.201": false,
		"192.0.0.192": true, "192.0.0.193": false, "FD00:EC2::254": true,
	} {
		if got := NeverProbed(h); got != want {
			t.Errorf("NeverProbed(%q) = %v, want %v", h, got, want)
		}
	}
}
