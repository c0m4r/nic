package dns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotRestoreAndValidation(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	originalPath := resolvConf
	resolvConf = filepath.Join(t.TempDir(), "resolv.conf")
	defer func() { resolvConf = originalPath }()

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
