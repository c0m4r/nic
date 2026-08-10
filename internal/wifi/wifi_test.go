package wifi

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/c0m4r/nic/internal/control"
)

func TestQuoteWPAValue(t *testing.T) {
	got, err := quoteWPAValue(`say "hello" \\ test`)
	if err != nil {
		t.Fatal(err)
	}
	if got != `"say \"hello\" \\\\ test"` {
		t.Fatalf("quoted value = %s", got)
	}
	if _, err := quoteWPAValue("bad\nvalue"); err == nil {
		t.Fatal("expected control-character error")
	}
}

func TestWPASupplicantConfigDoesNotRequirePassphraseHelper(t *testing.T) {
	originalDir := wpaConfDir
	wpaConfDir = t.TempDir()
	t.Cleanup(func() { wpaConfDir = originalDir })

	binDir := t.TempDir()
	writeExecutable := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(binDir, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	// Current wpa_passphrase requires a terminal when it reads a passphrase.
	// It must not be invoked by a non-interactive nic process.
	writeExecutable("wpa_passphrase", `echo should-not-run >&2
exit 1`)
	writeExecutable("wpa_supplicant", `pidfile=
while [ "$#" -gt 0 ]; do
    if [ "$1" = -P ]; then shift; pidfile=$1; fi
    shift
done
/bin/sleep 30 </dev/null >/dev/null 2>&1 &
printf '%s\n' "$!" > "$pidfile"`)
	t.Setenv("PATH", binDir)

	if err := connectWPASupplicant("Test", "topsecret", "wlan0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Disconnect("wlan0") })
	content, err := os.ReadFile(filepath.Join(wpaConfDir, "wlan0.conf"))
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	if !strings.Contains(string(content), `psk="topsecret"`) {
		t.Fatalf("generated config did not contain the quoted passphrase:\n%s", content)
	}
	if !strings.Contains(string(content), "key_mgmt=WPA-PSK SAE") {
		t.Fatalf("generated config did not enable WPA3 fallback:\n%s", content)
	}
	info, err := os.Stat(filepath.Join(wpaConfDir, "wlan0.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestIWDSSIDEncodingAndProfileRestore(t *testing.T) {
	if got := encodeIWDSSID("Cafe WiFi-1"); got != "Cafe WiFi-1" {
		t.Fatalf("plain encoding = %q", got)
	}
	if got := encodeIWDSSID("Cafe/1"); got != "=436166652f31" {
		t.Fatalf("hex encoding = %q", got)
	}

	originalDir := iwdProfileDir
	iwdProfileDir = t.TempDir()
	defer func() { iwdProfileDir = originalDir }()
	path := filepath.Join(iwdProfileDir, "Network.psk")
	if err := os.WriteFile(path, []byte("old"), 0640); err != nil {
		t.Fatal(err)
	}
	record, err := installIWDProfile("Network", "newpassword")
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreIWDProfile(record); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("restored profile = %q", got)
	}
}

func TestDisconnectWaitsForTrackedSupplicantBeforeRemovingFiles(t *testing.T) {
	originalDir := wpaConfDir
	wpaConfDir = t.TempDir()
	t.Cleanup(func() { wpaConfDir = originalDir })

	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	go func() { _ = cmd.Wait() }()

	record, err := control.RecordForPID(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wpaConfDir, "wlan0.pid"), []byte(strconv.Itoa(record.PID)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := control.WriteJSONAtomic(filepath.Join(wpaConfDir, "wlan0.pid.json"), record, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wpaConfDir, "wlan0.conf"), []byte("credentials"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := Disconnect("wlan0"); err != nil {
		t.Fatal(err)
	}
	if control.ProcessRecordIsLive(record) {
		t.Fatal("supplicant was still live after Disconnect returned")
	}
	for _, suffix := range []string{".pid", ".pid.json", ".conf"} {
		if _, err := os.Stat(filepath.Join(wpaConfDir, "wlan0"+suffix)); !os.IsNotExist(err) {
			t.Fatalf("managed file %s remained: %v", suffix, err)
		}
	}
}
