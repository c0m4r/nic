package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/c0m4r/nic/internal/config"
	"github.com/c0m4r/nic/internal/control"
	"github.com/c0m4r/nic/internal/executor"
	"github.com/c0m4r/nic/internal/state"
)

func TestReverseIPCommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			"link set up → down",
			[]string{"link", "set", "eth0", "up"},
			[]string{"link", "set", "eth0", "down"},
		},
		{
			"link set down stays down",
			[]string{"link", "set", "eth0", "down"},
			[]string{"link", "set", "eth0", "down"},
		},
		{
			"link add → link del",
			[]string{"link", "add", "bond0", "type", "bond"},
			[]string{"link", "del", "bond0"},
		},
		{
			"link add dev form deletes created link",
			[]string{"link", "add", "dev", "bond0", "type", "bond"},
			[]string{"link", "del", "bond0"},
		},
		{
			"link add without a name is not reversible",
			[]string{"link", "add", "type", "dummy"},
			nil,
		},
		{
			"address add → address del",
			[]string{"address", "add", "192.168.0.1/24", "dev", "eth0"},
			[]string{"address", "del", "192.168.0.1/24", "dev", "eth0"},
		},
		{
			"route add → route del",
			[]string{"route", "add", "default", "via", "192.168.0.1", "dev", "eth0"},
			[]string{"route", "del", "default", "via", "192.168.0.1", "dev", "eth0"},
		},
		{
			"too short returns nil",
			[]string{"link"},
			nil,
		},
		{
			"unknown returns nil",
			[]string{"neigh", "add", "1.2.3.4"},
			nil,
		},
		{
			"abbreviated address add",
			[]string{"a", "a", "192.0.2.1/24", "dev", "eth0"},
			[]string{"address", "del", "192.0.2.1/24", "dev", "eth0"},
		},
		{
			"vlan link add uses name",
			[]string{"link", "add", "link", "bond0", "name", "bond0.100", "type", "vlan", "id", "100"},
			[]string{"link", "del", "bond0.100"},
		},
		{
			"master becomes nomaster",
			[]string{"link", "set", "eth0", "master", "bond0"},
			[]string{"link", "set", "eth0", "nomaster"},
		},
		{
			"one-letter route abbreviation",
			[]string{"r", "a", "default", "via", "192.0.2.1"},
			[]string{"route", "del", "default", "via", "192.0.2.1"},
		},
		{
			"rule abbreviation",
			[]string{"ru", "a", "priority", "100", "from", "192.0.2.0/24"},
			[]string{"rule", "del", "priority", "100", "from", "192.0.2.0/24"},
		},
		{
			"IPv6 address add preserves family option",
			[]string{"-6", "address", "add", "2001:db8::1/64", "dev", "eth0"},
			[]string{"-6", "address", "del", "2001:db8::1/64", "dev", "eth0"},
		},
	}

	for _, tt := range tests {
		got := reverseIPCommand(tt.args)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: reverseIPCommand(%v) = %v, want %v", tt.name, tt.args, got, tt.want)
		}
	}
}

func TestValidateRollbackableIPCommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
		bad  bool
	}{
		{"link add", []string{"link", "add", "bond0", "type", "bond"}, false},
		{"link add dev form", []string{"link", "add", "dev", "bond0", "type", "bond"}, false},
		{"vlan add", []string{"link", "add", "link", "bond0", "name", "bond0.10", "type", "vlan", "id", "10"}, false},
		{"unnamed link add", []string{"link", "add", "type", "dummy"}, true},
		{"restorable link settings", []string{"link", "set", "dev", "eth0", "mtu", "1400", "master", "bond0", "up"}, false},
		{"IPv6 route", []string{"-6", "route", "add", "default", "via", "2001:db8::1", "dev", "eth0"}, false},
		{"link delete", []string{"link", "delete", "eth0"}, true},
		{"link rename", []string{"link", "set", "dev", "eth0", "name", "wan0"}, true},
		{"link netns move", []string{"link", "set", "dev", "eth0", "netns", "1"}, true},
		{"address delete", []string{"address", "delete", "192.0.2.1/24", "dev", "eth0"}, true},
		{"unsupported object", []string{"neigh", "add", "192.0.2.1", "lladdr", "00:11:22:33:44:55", "dev", "eth0"}, true},
	}
	for _, tt := range tests {
		err := validateRollbackableIPCommand(tt.args)
		if tt.bad && err == nil {
			t.Errorf("%s: expected rejection", tt.name)
		}
		if !tt.bad && err != nil {
			t.Errorf("%s: unexpected rejection: %v", tt.name, err)
		}
	}
}

func TestApplyConfigRejectsUnsafeIPCommandBeforeExecution(t *testing.T) {
	_, logPath := setupFakeRuntime(t)
	cfg := &config.Config{Commands: []config.Command{{
		Type: config.CmdIPRoute2,
		Raw:  "ip link set dev eth0 name wan0",
		Tokens: []string{
			"ip", "link", "set", "dev", "eth0", "name", "wan0",
		},
		File: "nic.conf", LineNum: 1,
	}}}
	if err := applyConfig(cfg, false); err == nil || !strings.Contains(err.Error(), "cannot be safely restored") {
		t.Fatalf("unsafe config error = %v", err)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("unsafe ip command ran, log error = %v", err)
	}
}

func TestParseChangeOptionsDefaultsToRollback(t *testing.T) {
	options, err := parseChangeOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if options.timeout != 10 {
		t.Fatalf("timeout = %d, want 10", options.timeout)
	}
	options, err = parseChangeOptions([]string{"--no-rollback", "--force"})
	if err != nil {
		t.Fatal(err)
	}
	if options.timeout != 0 || !options.force {
		t.Fatalf("options = %+v", options)
	}
}

func TestConfigDiffIdentityIncludesHiddenWifiPassword(t *testing.T) {
	first := config.Command{Type: config.CmdWifi, Tokens: []string{"wifi", "Cafe", "first-secret"}}
	second := config.Command{Type: config.CmdWifi, Tokens: []string{"wifi", "Cafe", "second-secret"}}
	if config.ExpandCommandString(first) != config.ExpandCommandString(second) {
		t.Fatal("human-readable WiFi command unexpectedly exposes the credential change")
	}
	if configCommandKey(first) == configCommandKey(second) {
		t.Fatal("configuration identity ignored a WiFi credential change")
	}
}

func TestValidateWifiConfigPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wifi.conf")
	if err := os.WriteFile(path, []byte("wifi ssid password\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Commands: []config.Command{{Type: config.CmdWifi, File: path}}}
	if err := validateWifiConfigPermissions(cfg); err == nil {
		t.Fatal("expected insecure WiFi config to be rejected")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateWifiConfigPermissions(cfg); err != nil {
		t.Fatalf("secure config rejected: %v", err)
	}
}

func TestReconcileReplacesAppliedConfiguration(t *testing.T) {
	runtimeDir, logPath := setupFakeRuntime(t)
	oldConfig := ipConfig("192.0.2.10/24")
	newConfig := ipConfig("192.0.2.20/24")

	if err := reconcileConfig(oldConfig, false); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if err := reconcileConfig(newConfig, false); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	applied, err := config.LoadSnapshot(control.AppliedConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := applied.Commands[0].Tokens[1]; got != "192.0.2.20/24" {
		t.Fatalf("applied address = %s", got)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logData)
	if !strings.Contains(log, "address del 192.0.2.10/24 dev eth0") ||
		!strings.Contains(log, "address add 192.0.2.20/24 dev eth0") {
		t.Fatalf("reconcile command log:\n%s", log)
	}
	if err := stopManagedConfig(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(runtimeDir, "applied.json")); !os.IsNotExist(err) {
		t.Fatalf("applied snapshot still exists: %v", err)
	}
}

func TestRestoreSavedSnapshotReappliesPreviousConfig(t *testing.T) {
	setupFakeRuntime(t)
	current := ipConfig("198.51.100.20/24")
	previous := ipConfig("198.51.100.10/24")
	if err := config.SaveSnapshot(control.AppliedConfigPath, current); err != nil {
		t.Fatal(err)
	}
	previousPath := filepath.Join(filepath.Dir(control.AppliedConfigPath), "previous.json")
	if err := config.SaveSnapshot(previousPath, previous); err != nil {
		t.Fatal(err)
	}
	if err := restoreSavedSnapshot(control.BaseStatePath, previousPath, false); err != nil {
		t.Fatal(err)
	}
	applied, err := config.LoadSnapshot(control.AppliedConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := applied.Commands[0].Tokens[1]; got != "198.51.100.10/24" {
		t.Fatalf("restored address = %s", got)
	}
}

func TestReconcileCleansInterruptedConfiguration(t *testing.T) {
	_, logPath := setupFakeRuntime(t)
	interrupted := ipConfig("203.0.113.10/24")
	if err := config.SaveSnapshot(control.PendingConfigPath, interrupted); err != nil {
		t.Fatal(err)
	}

	if err := reconcileConfig(ipConfig("203.0.113.20/24"), false); err != nil {
		t.Fatal(err)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "address del 203.0.113.10/24 dev eth0") {
		t.Fatalf("interrupted configuration was not torn down:\n%s", logData)
	}
	if _, err := os.Stat(control.PendingConfigPath); !os.IsNotExist(err) {
		t.Fatalf("pending snapshot still exists: %v", err)
	}
}

func TestNoManagedStateSnapshotsRequiresPendingStateToBeGone(t *testing.T) {
	setupFakeRuntime(t)
	if noManagedStateSnapshots() {
		t.Fatal("baseline snapshot was ignored")
	}
	if err := os.Remove(control.BaseStatePath); err != nil {
		t.Fatal(err)
	}
	if !noManagedStateSnapshots() {
		t.Fatal("missing snapshots were not recognized")
	}
	if err := os.WriteFile(control.PendingConfigPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if noManagedStateSnapshots() {
		t.Fatal("pending configuration was ignored")
	}
}

func TestNotifySystemdSendsReadinessDatagram(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox forbids Unix datagram socket binding")
		}
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	t.Setenv("NOTIFY_SOCKET", socket)

	if err := notifySystemd("READY=1\nSTATUS=test"); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, _, err := listener.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "READY=1\nSTATUS=test" {
		t.Fatalf("notification = %q", got)
	}
}

func TestDiscardStaleReloadArtifactsKeepsOnlyCurrentRequest(t *testing.T) {
	runtimeDir, _ := setupFakeRuntime(t)
	current := control.PIDRecord{PID: 100, StartTime: "current"}
	staleSnapshot := filepath.Join(runtimeDir, "reload-1-2.json")
	if err := os.WriteFile(staleSnapshot, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	stale := control.ReloadRequest{
		ID: "1-2", SnapshotPath: staleSnapshot,
		Daemon: control.PIDRecord{PID: 99, StartTime: "old"},
	}
	if err := control.WriteJSONAtomic(control.ReloadRequestPath, stale, 0600); err != nil {
		t.Fatal(err)
	}
	if err := control.WriteJSONAtomic(control.ReloadResponsePath, control.Response{ID: stale.ID}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := discardStaleReloadArtifacts(current); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{control.ReloadRequestPath, control.ReloadResponsePath, staleSnapshot} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("stale artifact %s remained: %v", path, err)
		}
	}

	currentSnapshot := filepath.Join(runtimeDir, "reload-3-4.json")
	if err := os.WriteFile(currentSnapshot, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	request := control.ReloadRequest{ID: "3-4", SnapshotPath: currentSnapshot, Daemon: current}
	if err := control.WriteJSONAtomic(control.ReloadRequestPath, request, 0600); err != nil {
		t.Fatal(err)
	}
	if err := discardStaleReloadArtifacts(current); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{control.ReloadRequestPath, currentSnapshot} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("current reload artifact %s was removed: %v", path, err)
		}
	}
}

func TestRunDaemonRejectsReloadForPreviousInstance(t *testing.T) {
	runtimeDir, _ := setupFakeRuntime(t)
	snapshotPath := filepath.Join(runtimeDir, "reload-5-6.json")
	if err := config.SaveSnapshot(snapshotPath, &config.Config{}); err != nil {
		t.Fatal(err)
	}
	request := control.ReloadRequest{
		ID: "5-6", SnapshotPath: snapshotPath,
		Daemon: control.PIDRecord{PID: os.Getpid(), StartTime: "previous-instance"},
	}
	if err := control.WriteJSONAtomic(control.ReloadRequestPath, request, 0600); err != nil {
		t.Fatal(err)
	}
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGHUP
	close(signals)
	if err := runDaemon("unused.conf", signals); err != nil {
		t.Fatal(err)
	}
	var response control.Response
	if err := control.ReadJSON(control.ReloadResponsePath, &response); err != nil {
		t.Fatal(err)
	}
	if response.ID != request.ID || !strings.Contains(response.Error, "different daemon instance") {
		t.Fatalf("response = %+v", response)
	}
	if _, err := os.Stat(snapshotPath); !os.IsNotExist(err) {
		t.Fatalf("stale snapshot remained: %v", err)
	}
}

func TestDaemonStartupTerminationCancelsRunningCommand(t *testing.T) {
	runtimeDir, _ := setupFakeRuntime(t)
	marker := filepath.Join(runtimeDir, "command-started")
	script := "#!/bin/sh\nif [ ! -e " + marker + " ]; then\n" +
		"  /usr/bin/touch " + marker + "\n" +
		"  /bin/sleep 30\n" +
		"fi\nexit 0\n"
	if err := os.WriteFile(filepath.Join(runtimeDir, "bin", "ip"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	startupCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	restore := executor.UseCommandContext(startupCtx)
	signals := make(chan os.Signal, 1)
	go func() {
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(marker); err == nil {
				signals <- syscall.SIGTERM
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		signals <- syscall.SIGTERM
	}()

	started := time.Now()
	stopped, err := reconcileDaemonStartup(&config.Config{}, signals, cancel, restore)
	if err != nil {
		t.Fatal(err)
	}
	if !stopped {
		t.Fatal("startup reconciliation did not report termination")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("startup termination took %v; running command was not cancelled", elapsed)
	}
}

func setupFakeRuntime(t *testing.T) (string, string) {
	t.Helper()
	runtimeDir := t.TempDir()
	oldPaths := []string{
		control.RunDir, control.PIDPath, control.AppliedConfigPath, control.PendingConfigPath, control.BaseStatePath,
		control.ReloadRequestPath, control.ReloadResponsePath, control.ReloadLockPath, control.RevertResponsePath,
	}
	control.RunDir = runtimeDir
	control.PIDPath = filepath.Join(runtimeDir, "nic.pid")
	control.AppliedConfigPath = filepath.Join(runtimeDir, "applied.json")
	control.PendingConfigPath = filepath.Join(runtimeDir, "pending.json")
	control.BaseStatePath = filepath.Join(runtimeDir, "base.json")
	control.ReloadRequestPath = filepath.Join(runtimeDir, "request.json")
	control.ReloadResponsePath = filepath.Join(runtimeDir, "response.json")
	control.ReloadLockPath = filepath.Join(runtimeDir, "reload.lock")
	control.RevertResponsePath = filepath.Join(runtimeDir, "revert-response.json")
	t.Cleanup(func() {
		control.RunDir = oldPaths[0]
		control.PIDPath = oldPaths[1]
		control.AppliedConfigPath = oldPaths[2]
		control.PendingConfigPath = oldPaths[3]
		control.BaseStatePath = oldPaths[4]
		control.ReloadRequestPath = oldPaths[5]
		control.ReloadResponsePath = oldPaths[6]
		control.ReloadLockPath = oldPaths[7]
		control.RevertResponsePath = oldPaths[8]
	})

	snapshot := state.NetworkState{}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(control.BaseStatePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(runtimeDir, "bin")
	if err := os.Mkdir(binDir, 0700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(runtimeDir, "ip.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + logPath + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(binDir, "ip"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	return runtimeDir, logPath
}

func ipConfig(address string) *config.Config {
	return &config.Config{Commands: []config.Command{{
		Type: config.CmdIPShortcut, Tokens: []string{"ip", address, "eth0"}, Raw: "ip " + address + " eth0",
	}}}
}
