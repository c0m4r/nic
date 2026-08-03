package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c0m4r/nic/internal/dns"
)

func TestCapturePropagatesIPFailure(t *testing.T) {
	dir := t.TempDir()
	writeFakeIP(t, dir, "#!/bin/sh\necho denied >&2\nexit 1\n")
	t.Setenv("PATH", dir)
	if _, err := Capture(); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("Capture error = %v", err)
	}
}

func TestRestorePropagatesCommandFailure(t *testing.T) {
	dir := t.TempDir()
	writeFakeIP(t, dir, "#!/bin/sh\necho restore-failed >&2\nexit 1\n")
	t.Setenv("PATH", dir)
	statePath := filepath.Join(dir, "state.json")
	snapshot := NetworkState{
		Interfaces: []Interface{{IfName: "eth0", MTU: 1500}},
		DNS:        dns.Snapshot{},
	}
	data, _ := json.Marshal(snapshot)
	if err := os.WriteFile(statePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreState(statePath); err == nil || !strings.Contains(err.Error(), "restore-failed") {
		t.Fatalf("RestoreState error = %v", err)
	}
}

func writeFakeIP(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
}
