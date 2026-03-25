package wifi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/c0m4r/nic/internal/executor"
)

const (
	wpaConfDir = "/run/nic/wifi"
)

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
	_, _ = executor.RunIP("link", "set", iface, "up")

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
	_ = os.MkdirAll(wpaConfDir, 0700)
	confFile := filepath.Join(wpaConfDir, iface+".conf")

	// Generate config using wpa_passphrase if available
	var confContent string
	if executor.CommandExists("wpa_passphrase") {
		output, err := executor.Run("wpa_passphrase", ssid, password)
		if err != nil {
			return fmt.Errorf("wpa_passphrase failed: %w", err)
		}
		confContent = "ctrl_interface=/run/nic/wpa_ctrl\n" + output
	} else {
		// Manual config — supports WPA2/WPA3
		confContent = fmt.Sprintf(`ctrl_interface=/run/nic/wpa_ctrl

network={
    ssid="%s"
    psk="%s"
    key_mgmt=WPA-PSK SAE
    ieee80211w=1
}
`, ssid, password)
	}

	if err := os.WriteFile(confFile, []byte(confContent), 0600); err != nil {
		return fmt.Errorf("write wpa config: %w", err)
	}

	// Kill any existing wpa_supplicant on this interface
	_ = Disconnect(iface)

	_, err := executor.Run("wpa_supplicant", "-B",
		"-i", iface,
		"-c", confFile,
		"-P", filepath.Join(wpaConfDir, iface+".pid"),
	)
	if err != nil {
		return fmt.Errorf("wpa_supplicant failed: %w", err)
	}

	fmt.Printf("WiFi: connected to %q on %s (wpa_supplicant)\n", ssid, iface)
	return nil
}

func connectIWD(ssid, password, iface string) error {
	_, err := executor.Run("iwctl", "station", iface, "connect", ssid,
		"--passphrase", password)
	if err != nil {
		return fmt.Errorf("iwctl connect failed: %w", err)
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

	// Kill wpa_supplicant
	pidFile := filepath.Join(wpaConfDir, iface+".pid")
	if data, err := os.ReadFile(pidFile); err == nil {
		pid := strings.TrimSpace(string(data))
		_, _ = executor.Run("kill", pid)
		_ = os.Remove(pidFile)
	}

	// Try iwctl disconnect
	if executor.CommandExists("iwctl") {
		_, _ = executor.Run("iwctl", "station", iface, "disconnect")
	}

	return nil
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
