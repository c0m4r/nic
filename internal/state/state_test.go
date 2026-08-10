package state

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestPrintStatusPropagatesIPFailure(t *testing.T) {
	dir := t.TempDir()
	writeFakeIP(t, dir, "#!/bin/sh\necho status-denied >&2\nexit 1\n")
	t.Setenv("PATH", dir)
	if err := PrintStatus(&bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "status-denied") {
		t.Fatalf("PrintStatus error = %v", err)
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

func TestRestorePreservesAddressLifetimes(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "ip.log")
	writeFakeIP(t, dir, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+logPath+"\n")
	t.Setenv("PATH", dir)
	statePath := filepath.Join(dir, "state.json")
	snapshot := NetworkState{
		Interfaces: []Interface{{IfName: "eth0", MTU: 1500}},
		Addresses: []AddrEntry{{IfName: "eth0", AddrInfo: []AddrInfo{{
			Family: "inet", Local: "192.0.2.25", PrefixLen: 24, Scope: "global",
			ValidLifeTime: json.RawMessage(`120`), PreferredLifeTime: json.RawMessage(`60`),
		}}}},
		DNS: dns.Snapshot{},
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreState(statePath); err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "addr replace 192.0.2.25/24 dev eth0 valid_lft 120 preferred_lft 60") {
		t.Fatalf("restored address omitted lifetimes:\n%s", log)
	}
}

func TestRestoreSkipsAddressWhoseCapturedLifetimeExpired(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "ip.log")
	writeFakeIP(t, dir, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+logPath+"\n")
	t.Setenv("PATH", dir)
	statePath := filepath.Join(dir, "state.json")
	snapshot := NetworkState{
		CapturedAt: time.Now().Add(-2 * time.Minute),
		Interfaces: []Interface{{IfName: "eth0", MTU: 1500}},
		Addresses: []AddrEntry{{IfName: "eth0", AddrInfo: []AddrInfo{{
			Family: "inet", Local: "192.0.2.99", PrefixLen: 24, Scope: "global",
			ValidLifeTime: json.RawMessage(`60`), PreferredLifeTime: json.RawMessage(`30`),
		}}}},
		DNS: dns.Snapshot{},
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreState(statePath); err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), "192.0.2.99/24") {
		t.Fatalf("expired address was restored:\n%s", log)
	}
}

func TestRestoreLifetimeArgsReducesRemainingLifetime(t *testing.T) {
	addr := AddrInfo{
		ValidLifeTime:     json.RawMessage(`120`),
		PreferredLifeTime: json.RawMessage(`60`),
	}
	args, restore, err := restoreLifetimeArgs(addr, 30)
	if err != nil {
		t.Fatal(err)
	}
	if !restore || strings.Join(args, " ") != "valid_lft 90 preferred_lft 30" {
		t.Fatalf("restoreLifetimeArgs = %v, %v; want adjusted lifetimes", args, restore)
	}
}

func TestLifetimeArgument(t *testing.T) {
	tests := []struct {
		value json.RawMessage
		want  string
		bad   bool
	}{
		{json.RawMessage(`120`), "120", false},
		{json.RawMessage(`"forever"`), "forever", false},
		{nil, "", false},
		{json.RawMessage(`-1`), "", true},
	}
	for _, tt := range tests {
		got, err := lifetimeArgument(tt.value)
		if tt.bad {
			if err == nil {
				t.Fatalf("lifetimeArgument(%s) unexpectedly succeeded", tt.value)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Fatalf("lifetimeArgument(%s) = %q, %v; want %q", tt.value, got, err, tt.want)
		}
	}
}

func writeFakeIP(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
}
