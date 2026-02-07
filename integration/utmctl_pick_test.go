//go:build integration

package integration

import "testing"

func TestParseUTMCtlIPOutput_CIDR(t *testing.T) {
	ip4, any := parseUTMCtlIPOutput("192.168.64.10/24\n")
	if ip4 != "192.168.64.10" || any != "192.168.64.10" {
		t.Fatalf("unexpected: ip4=%q any=%q", ip4, any)
	}
}

func TestParseUTMCtlIPOutput_LabelAndComma(t *testing.T) {
	ip4, any := parseUTMCtlIPOutput("IP address: 192.168.64.11,\n")
	if ip4 != "192.168.64.11" || any != "192.168.64.11" {
		t.Fatalf("unexpected: ip4=%q any=%q", ip4, any)
	}
}

func TestPickUTMVMIdentifier_WindowsPreference(t *testing.T) {
	vms := []utmVM{
		{UUID: "u1", Name: "ci-Linux"},
		{UUID: "u2", Name: "ci-Windows"},
		{UUID: "u3", Name: "other"},
	}
	got := pickUTMVMIdentifier(vms)
	if got != "ci-Windows" {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestPickUTMLinuxVMIdentifier_LinuxPreference(t *testing.T) {
	vms := []utmVM{
		{UUID: "u1", Name: "ci-Windows"},
		{UUID: "u2", Name: "ci-Linux"},
		{UUID: "u3", Name: "ci-Ubuntu"},
	}
	got := pickUTMLinuxVMIdentifier(vms)
	// Prefer Linux first match in CI list order (as returned by utmctl list).
	if got != "ci-Linux" && got != "ci-Ubuntu" {
		t.Fatalf("unexpected: %q", got)
	}
}
