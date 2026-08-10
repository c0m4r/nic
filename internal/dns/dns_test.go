package dns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotRestoreAndValidation(t *testing.T) {
	useTempResolvConf(t)

	original := []byte("nameserver 192.0.2.53\nsearch example.test\n")
	if err := os.WriteFile(resolvConf, original, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Capture()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteResolvConf([]string{"2001:db8::53"}); err != nil {
		t.Fatal(err)
	}
	if err := Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(resolvConf)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("restored contents = %q", got)
	}
	if err := WriteResolvConf([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected invalid nameserver error")
	}
}

func TestManagedNameserversKeepStaticDNSAcrossDHCPRenewals(t *testing.T) {
	useTempResolvConf(t)

	if err := SetLeaseNameservers("dhcp6:wan", []string{"2001:db8::53", "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if err := SetLeaseNameservers("dhcp4:wan", []string{"8.8.8.8", "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	assertNameservers(t, []string{"8.8.8.8", "1.1.1.1", "2001:db8::53"})

	if err := SetStaticNameservers([]string{"9.9.9.9"}); err != nil {
		t.Fatal(err)
	}
	// A later DHCP renewal must update its own source only, not replace static
	// resolver policy or race the v6 source.
	if err := SetLeaseNameservers("dhcp4:wan", []string{"4.4.4.4"}); err != nil {
		t.Fatal(err)
	}
	assertNameservers(t, []string{"9.9.9.9"})

	if err := SetStaticNameservers(nil); err != nil {
		t.Fatal(err)
	}
	assertNameservers(t, []string{"4.4.4.4", "2001:db8::53", "1.1.1.1"})
	if err := RemoveLeaseNameservers("dhcp4:wan"); err != nil {
		t.Fatal(err)
	}
	assertNameservers(t, []string{"2001:db8::53", "1.1.1.1"})
}

func TestConfiguredStaticPolicyPrecedesDHCPWithoutWritingEarly(t *testing.T) {
	useTempResolvConf(t)
	if err := ConfigureStaticNameservers([]string{"9.9.9.9"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(resolvConf); !os.IsNotExist(err) {
		t.Fatalf("resolver was written before configuration completed: %v", err)
	}
	if err := SetLeaseNameservers("dhcp4:wan", []string{"1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	assertNameservers(t, []string{"9.9.9.9"})
}

func TestManagedStateSurvivesMachineSnapshotRestore(t *testing.T) {
	useTempResolvConf(t)
	if err := os.WriteFile(resolvConf, []byte("nameserver 192.0.2.53\n"), 0600); err != nil {
		t.Fatal(err)
	}
	machineSnapshot, err := Capture()
	if err != nil {
		t.Fatal(err)
	}
	if err := SetLeaseNameservers("dhcp4:wan", []string{"1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if err := SetLeaseNameservers("dhcp6:wan", []string{"2001:db8::53"}); err != nil {
		t.Fatal(err)
	}
	if err := SetStaticNameservers([]string{"9.9.9.9"}); err != nil {
		t.Fatal(err)
	}
	managedSnapshot := CaptureManagedState()

	if err := Restore(machineSnapshot); err != nil {
		t.Fatal(err)
	}
	assertNameservers(t, []string{"192.0.2.53"})
	if err := RestoreManagedState(managedSnapshot); err != nil {
		t.Fatal(err)
	}
	assertNameservers(t, []string{"9.9.9.9"})

	// Clearing static policy after rollback exposes both preserved DHCP
	// contributors, proving the manager did not retain only the rendered file.
	if err := SetStaticNameservers(nil); err != nil {
		t.Fatal(err)
	}
	assertNameservers(t, []string{"1.1.1.1", "2001:db8::53"})
}

func useTempResolvConf(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	originalPath := resolvConf
	resolvConf = filepath.Join(t.TempDir(), "resolv.conf")
	ResetManagedNameservers()
	t.Cleanup(func() {
		resolvConf = originalPath
		ResetManagedNameservers()
	})
}

func assertNameservers(t *testing.T, want []string) {
	t.Helper()
	got := CurrentNameservers()
	if len(got) != len(want) {
		t.Fatalf("nameservers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("nameservers = %v, want %v", got, want)
		}
	}
}
