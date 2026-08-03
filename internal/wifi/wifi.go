package wifi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/c0m4r/nic/internal/control"
	"github.com/c0m4r/nic/internal/executor"
)

var (
	wpaConfDir    = "/run/nic/wifi"
	iwdProfileDir = "/var/lib/iwd"
)

type iwdProfileRecord struct {
	Path    string      `json:"path"`
	Existed bool        `json:"existed"`
	Content []byte      `json:"content,omitempty"`
	Mode    os.FileMode `json:"mode,omitempty"`
}

// DetectInterface finds the first wireless interface on the system.
func DetectInterface() string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		wirelessPath := filepath.Join("/sys/class/net", entry.Name(), "wireless")
		if _, err := os.Stat(wirelessPath); err == nil {
			return entry.Name()
		}
		// Also check phy80211 symlink
		phy80211 := filepath.Join("/sys/class/net", entry.Name(), "phy80211")
		if _, err := os.Stat(phy80211); err == nil {
			return entry.Name()
		}
	}
	return ""
}

// Connect connects to a WiFi network using the best available method.
func Connect(ssid, password, iface string) error {
	if iface == "" {
		iface = DetectInterface()
		if iface == "" {
			return fmt.Errorf("no wireless interface found")
		}
	}

	if executor.DryRun {
		fmt.Printf("[dry-run] wifi connect to %q on %s\n", ssid, iface)
		return nil
	}

	// Bring up the interface
	if _, err := executor.RunIP("link", "set", iface, "up"); err != nil {
		return fmt.Errorf("bring up %s: %w", iface, err)
	}

	// Try backends in order of preference
	if executor.CommandExists("wpa_supplicant") {
		return connectWPASupplicant(ssid, password, iface)
	}
	if executor.CommandExists("iwctl") {
		return connectIWD(ssid, password, iface)
	}

	return fmt.Errorf("no WiFi backend available; install wpa_supplicant or iwd\n" +
		"  Debian/Ubuntu: apt install wpasupplicant\n" +
		"  Arch:          pacman -S wpa_supplicant\n" +
		"  Alpine:        apk add wpa_supplicant")
}

func connectWPASupplicant(ssid, password, iface string) error {
	// Stop a previous backend before replacing its credentials. Disconnect also
	// removes nic's old wpa_supplicant configuration for this interface.
	if err := Disconnect(iface); err != nil {
		return err
	}
	if err := os.MkdirAll(wpaConfDir, 0700); err != nil {
		return err
	}
	confFile := filepath.Join(wpaConfDir, iface+".conf")

	// Generate config using wpa_passphrase if available
	var confContent string
	if executor.CommandExists("wpa_passphrase") {
		output, err := executor.RunWithInput("wpa_passphrase", password+"\n", ssid)
		if err != nil {
			return fmt.Errorf("wpa_passphrase failed: %w", err)
		}
		var safeLines []string
		for _, line := range strings.Split(output, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "#psk=") {
				safeLines = append(safeLines, line)
			}
		}
		confContent = "ctrl_interface=/run/nic/wpa_ctrl\n" + strings.Join(safeLines, "\n")
	} else {
		// Manual config — supports WPA2/WPA3
		quotedSSID, err := quoteWPAValue(ssid)
		if err != nil {
			return fmt.Errorf("invalid SSID: %w", err)
		}
		quotedPassword, err := quoteWPAValue(password)
		if err != nil {
			return fmt.Errorf("invalid passphrase: %w", err)
		}
		confContent = fmt.Sprintf(`ctrl_interface=/run/nic/wpa_ctrl

network={
    ssid=%s
    psk=%s
    key_mgmt=WPA-PSK SAE
    ieee80211w=1
}
`, quotedSSID, quotedPassword)
	}

	if err := os.WriteFile(confFile, []byte(confContent), 0600); err != nil {
		return fmt.Errorf("write wpa config: %w", err)
	}

	_, err := executor.Run("wpa_supplicant", "-B",
		"-i", iface,
		"-c", confFile,
		"-P", filepath.Join(wpaConfDir, iface+".pid"),
	)
	if err != nil {
		_ = os.Remove(confFile)
		return fmt.Errorf("wpa_supplicant failed: %w", err)
	}
	pidPath := filepath.Join(wpaConfDir, iface+".pid")
	data, readErr := os.ReadFile(pidPath)
	if readErr != nil {
		_ = Disconnect(iface)
		return fmt.Errorf("read wpa_supplicant pid: %w", readErr)
	}
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
	if parseErr != nil || pid <= 0 {
		_ = Disconnect(iface)
		return fmt.Errorf("invalid wpa_supplicant pid in %s", pidPath)
	}
	record, recordErr := control.RecordForPID(pid)
	if recordErr != nil {
		_ = Disconnect(iface)
		return fmt.Errorf("record wpa_supplicant process: %w", recordErr)
	}
	if writeErr := control.WriteJSONAtomic(filepath.Join(wpaConfDir, iface+".pid.json"), record, 0600); writeErr != nil {
		_ = Disconnect(iface)
		return fmt.Errorf("record wpa_supplicant process: %w", writeErr)
	}

	fmt.Printf("WiFi: connected to %q on %s (wpa_supplicant)\n", ssid, iface)
	return nil
}

func connectIWD(ssid, password, iface string) error {
	if len(password) < 8 || len(password) > 63 {
		return fmt.Errorf("iwd requires a WPA passphrase between 8 and 63 characters")
	}
	if _, err := quoteWPAValue(password); err != nil {
		return fmt.Errorf("invalid passphrase: %w", err)
	}
	if err := Disconnect(iface); err != nil {
		return err
	}
	record, err := installIWDProfile(ssid, password)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(wpaConfDir, 0700); err != nil {
		_ = restoreIWDProfile(record)
		return err
	}
	recordPath := filepath.Join(wpaConfDir, iface+".iwd.json")
	if err := control.WriteJSONAtomic(recordPath, record, 0600); err != nil {
		_ = restoreIWDProfile(record)
		return err
	}

	_, err = executor.Run("iwctl", "station", iface, "connect", ssid)
	if err != nil {
		restoreErr := restoreIWDProfile(record)
		if restoreErr == nil {
			_ = os.Remove(recordPath)
		}
		return errors.Join(fmt.Errorf("iwctl connect failed: %w", err), restoreErr)
	}
	fmt.Printf("WiFi: connected to %q on %s (iwd)\n", ssid, iface)
	return nil
}

// Disconnect disconnects WiFi on the given interface.
func Disconnect(iface string) error {
	if executor.DryRun {
		fmt.Printf("[dry-run] wifi disconnect %s\n", iface)
		return nil
	}

	var disconnectErrors []error
	// Kill wpa_supplicant
	pidFile := filepath.Join(wpaConfDir, iface+".pid")
	if data, err := os.ReadFile(pidFile); err == nil {
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
		recordFile := filepath.Join(wpaConfDir, iface+".pid.json")
		record, recordErr := control.ReadProcessRecord(recordFile)
		if recordErr == nil && record.PID == pid {
			if err := control.SignalProcessRecord(record, syscall.SIGTERM); err != nil && !errors.Is(err, control.ErrNotRunning) {
				disconnectErrors = append(disconnectErrors, err)
			}
		} else if parseErr == nil && pid > 0 {
			if name, nameErr := control.ProcessExecutableName(pid); nameErr == nil && name == "wpa_supplicant" {
				if proc, findErr := os.FindProcess(pid); findErr == nil {
					if err := proc.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
						disconnectErrors = append(disconnectErrors, err)
					}
				}
			}
		}
		_ = os.Remove(pidFile)
		_ = os.Remove(recordFile)
	}
	_ = os.Remove(filepath.Join(wpaConfDir, iface+".conf"))

	recordPath := filepath.Join(wpaConfDir, iface+".iwd.json")
	if data, err := os.ReadFile(recordPath); err == nil {
		if executor.CommandExists("iwctl") {
			if _, err := executor.Run("iwctl", "station", iface, "disconnect"); err != nil {
				disconnectErrors = append(disconnectErrors, err)
			}
		}
		var record iwdProfileRecord
		restored := false
		if err := json.Unmarshal(data, &record); err != nil {
			disconnectErrors = append(disconnectErrors, fmt.Errorf("read iwd profile record: %w", err))
		} else if err := restoreIWDProfile(record); err != nil {
			disconnectErrors = append(disconnectErrors, fmt.Errorf("restore iwd profile: %w", err))
		} else {
			restored = true
		}
		if restored {
			_ = os.Remove(recordPath)
		}
	} else if !os.IsNotExist(err) {
		disconnectErrors = append(disconnectErrors, err)
	}

	return errors.Join(disconnectErrors...)
}

// ManagedInterfaces returns interfaces for which nic has backend state.
func ManagedInterfaces() []string {
	entries, err := os.ReadDir(wpaConfDir)
	if err != nil {
		return nil
	}
	managed := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		for _, suffix := range []string{".pid.json", ".pid", ".iwd.json", ".conf"} {
			if strings.HasSuffix(name, suffix) {
				iface := strings.TrimSuffix(name, suffix)
				if iface != "" {
					managed[iface] = true
				}
				break
			}
		}
	}
	interfaces := make([]string, 0, len(managed))
	for iface := range managed {
		interfaces = append(interfaces, iface)
	}
	sort.Strings(interfaces)
	return interfaces
}

func installIWDProfile(ssid, password string) (iwdProfileRecord, error) {
	if err := os.MkdirAll(iwdProfileDir, 0700); err != nil {
		return iwdProfileRecord{}, err
	}
	path := filepath.Join(iwdProfileDir, encodeIWDSSID(ssid)+".psk")
	record := iwdProfileRecord{Path: path}
	if info, err := os.Stat(path); err == nil {
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return iwdProfileRecord{}, readErr
		}
		record.Existed = true
		record.Content = content
		record.Mode = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return iwdProfileRecord{}, err
	}
	content := []byte("[Security]\nPassphrase=" + password + "\n")
	if err := writeFileAtomic(path, content, 0600); err != nil {
		return iwdProfileRecord{}, err
	}
	return record, nil
}

func restoreIWDProfile(record iwdProfileRecord) error {
	if record.Path == "" || filepath.Dir(record.Path) != filepath.Clean(iwdProfileDir) {
		return fmt.Errorf("invalid iwd profile record")
	}
	if !record.Existed {
		if err := os.Remove(record.Path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return writeFileAtomic(record.Path, record.Content, record.Mode)
}

func encodeIWDSSID(ssid string) string {
	plain := ssid != ""
	for _, b := range []byte(ssid) {
		if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
			(b >= '0' && b <= '9') || b == ' ' || b == '_' || b == '-') {
			plain = false
			break
		}
	}
	if plain {
		return ssid
	}
	return "=" + hex.EncodeToString([]byte(ssid))
}

func writeFileAtomic(path string, content []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nic-wifi-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func quoteWPAValue(value string) (string, error) {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("control characters are not supported")
		}
	}
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`, nil
}

// Status returns WiFi status information.
func Status() string {
	iface := DetectInterface()
	if iface == "" {
		return "No wireless interface found"
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("Interface: %s", iface))

	// Try iw for connection info
	if executor.CommandExists("iw") {
		output := executor.RunSilent("iw", "dev", iface, "link")
		if strings.Contains(output, "Not connected") {
			lines = append(lines, "Status: not connected")
		} else {
			for _, line := range strings.Split(output, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "SSID:") ||
					strings.HasPrefix(line, "signal:") ||
					strings.HasPrefix(line, "freq:") ||
					strings.HasPrefix(line, "tx bitrate:") {
					lines = append(lines, "  "+line)
				}
			}
		}
	}

	return strings.Join(lines, "\n")
}
