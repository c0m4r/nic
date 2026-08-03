package wifi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestWPASupplicantConfigSurvivesBackendCleanup(t *testing.T) {
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
	writeExecutable("wpa_passphrase", `read -r password
printf 'network={\n\tssid="Test"\n\t#psk="%s"\n\tpsk=hash\n}\n' "$password"`)
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
	if strings.Contains(string(content), "topsecret") {
		t.Fatal("generated config retained the plaintext passphrase")
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
