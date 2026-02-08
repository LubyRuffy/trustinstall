//go:build integration || all_platform

package integration

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverDarwinVMIPv4ByDHCPLeases_PickNewestByLease(t *testing.T) {
	content := `
{
	name=cidexuniji
	ip_address=192.168.64.4
	lease=0x10
}
{
	name=cidexuniji
	ip_address=192.168.65.2
	lease=0x20
}
{
	name=ci-macOS
	ip_address=192.168.64.9
	lease=0x01
}
`
	tmp := t.TempDir()
	p := filepath.Join(tmp, "dhcpd_leases")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write tmp lease file err=%v", err)
	}
	t.Setenv("TRUSTINSTALL_DARWIN_DHCPD_LEASES", p)

	ip, err := discoverDarwinVMIPv4ByDHCPLeases([]string{"cidexuniji", "ci-macOS"})
	if err != nil {
		t.Fatalf("discover err=%v", err)
	}
	if ip != "192.168.65.2" {
		t.Fatalf("unexpected ip=%s", ip)
	}
}
