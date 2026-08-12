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

// A sit tunnel reports a 4-byte link address and rejects every attempt to
// change it, so restoring the address it already has must not be attempted.
func TestRestoreSkipsUnchangedLinkProperties(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "ip.log")
	writeFakeIP(t, dir, `#!/bin/sh
printf '%s\n' "$*" >> `+logPath+`
case "$*" in
"-j link show")
	echo '[{"ifindex":3,"ifname":"sit0","flags":["NOARP"],"mtu":1480,"address":"0.0.0.0","operstate":"DOWN","link_type":"sit"}]'
	;;
*"link set dev sit0 address"*)
	echo "RTNETLINK answers: Operation not supported" >&2
	exit 2
	;;
esac
exit 0
`)
	t.Setenv("PATH", dir)
	statePath := filepath.Join(dir, "state.json")
	snapshot := NetworkState{
		Interfaces: []Interface{{IfIndex: 3, IfName: "sit0", MTU: 1480, Address: "0.0.0.0", Link: "sit"}},
		DNS:        dns.Snapshot{},
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreState(statePath); err != nil {
		t.Fatalf("RestoreState error = %v", err)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), "link set dev sit0 address") {
		t.Fatalf("unchanged link address was rewritten:\n%s", log)
	}
	if strings.Contains(string(log), "link set dev sit0 mtu") {
		t.Fatalf("unchanged MTU was rewritten:\n%s", log)
	}
}

func TestRestoreRewritesDriftedLinkProperties(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "ip.log")
	writeFakeIP(t, dir, `#!/bin/sh
printf '%s\n' "$*" >> `+logPath+`
case "$*" in
"-j link show")
	echo '[{"ifindex":2,"ifname":"eth0","flags":["BROADCAST"],"mtu":1500,"address":"52:54:00:12:34:56","operstate":"DOWN","link_type":"ether"}]'
	;;
esac
exit 0
`)
	t.Setenv("PATH", dir)
	statePath := filepath.Join(dir, "state.json")
	snapshot := NetworkState{
		Interfaces: []Interface{{IfIndex: 2, IfName: "eth0", MTU: 9000, Address: "52:54:00:ab:cd:ef", Link: "ether"}},
		DNS:        dns.Snapshot{},
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreState(statePath); err != nil {
		t.Fatalf("RestoreState error = %v", err)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "link set dev eth0 address 52:54:00:ab:cd:ef") {
		t.Fatalf("drifted link address was not restored:\n%s", log)
	}
	if !strings.Contains(string(log), "link set dev eth0 mtu 9000") {
		t.Fatalf("drifted MTU was not restored:\n%s", log)
	}
}

func TestHasGlobalAddress(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{{
		name:   "global scope counts",
		output: `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"10.0.2.15","scope":"global"}]}]`,
		want:   true,
	}, {
		name:   "universe scope counts",
		output: `[{"ifname":"eth0","addr_info":[{"family":"inet6","local":"2001:db8::1","scope":"universe"}]}]`,
		want:   true,
	}, {
		name:   "link-local does not count",
		output: `[{"ifname":"eth0","addr_info":[{"family":"inet6","local":"fe80::1","scope":"link"}]}]`,
	}, {
		name:   "host scope does not count",
		output: `[{"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","scope":"host"}]}]`,
	}, {
		name:   "tentative address does not count",
		output: `[{"ifname":"eth0","addr_info":[{"family":"inet6","local":"2001:db8::1","scope":"global","tentative":true}]}]`,
	}, {
		name:   "no addresses",
		output: `[{"ifname":"eth0","addr_info":[]}]`,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFakeIP(t, dir, "#!/bin/sh\necho '"+tt.output+"'\n")
			t.Setenv("PATH", dir)
			got, err := HasGlobalAddress("eth0")
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("HasGlobalAddress = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasGlobalAddressPropagatesFailure(t *testing.T) {
	dir := t.TempDir()
	writeFakeIP(t, dir, "#!/bin/sh\necho no-such-device >&2\nexit 1\n")
	t.Setenv("PATH", dir)
	if _, err := HasGlobalAddress("eth0"); err == nil || !strings.Contains(err.Error(), "no-such-device") {
		t.Fatalf("HasGlobalAddress error = %v", err)
	}
}

func writeFakeIP(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
}
