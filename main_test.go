package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/c0m4r/nic/internal/config"
	"github.com/c0m4r/nic/internal/control"
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
	}

	for _, tt := range tests {
		got := reverseIPCommand(tt.args)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: reverseIPCommand(%v) = %v, want %v", tt.name, tt.args, got, tt.want)
		}
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

func setupFakeRuntime(t *testing.T) (string, string) {
	t.Helper()
	runtimeDir := t.TempDir()
	oldPaths := []string{
		control.RunDir, control.PIDPath, control.AppliedConfigPath, control.PendingConfigPath, control.BaseStatePath,
		control.ReloadRequestPath, control.ReloadResponsePath, control.RevertResponsePath,
	}
	control.RunDir = runtimeDir
	control.PIDPath = filepath.Join(runtimeDir, "nic.pid")
	control.AppliedConfigPath = filepath.Join(runtimeDir, "applied.json")
	control.PendingConfigPath = filepath.Join(runtimeDir, "pending.json")
	control.BaseStatePath = filepath.Join(runtimeDir, "base.json")
	control.ReloadRequestPath = filepath.Join(runtimeDir, "request.json")
	control.ReloadResponsePath = filepath.Join(runtimeDir, "response.json")
	control.RevertResponsePath = filepath.Join(runtimeDir, "revert-response.json")
	t.Cleanup(func() {
		control.RunDir = oldPaths[0]
		control.PIDPath = oldPaths[1]
		control.AppliedConfigPath = oldPaths[2]
		control.PendingConfigPath = oldPaths[3]
		control.BaseStatePath = oldPaths[4]
		control.ReloadRequestPath = oldPaths[5]
		control.ReloadResponsePath = oldPaths[6]
		control.RevertResponsePath = oldPaths[7]
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
