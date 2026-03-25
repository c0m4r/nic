package dhcp

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/c0m4r/nic/internal/executor"
)

var externalClients = []string{"dhclient", "dhcpcd", "udhcpc"}

func detectExternalClient() string {
	for _, c := range externalClients {
		if executor.CommandExists(c) {
			return c
		}
	}
	return ""
}

func isExternalClient(name string) bool {
	for _, c := range externalClients {
		if name == c {
			return true
		}
	}
	return false
}

func startExternal(iface, client string) error {
	if client == "" {
		client = detectExternalClient()
	}
	if client == "" {
		return fmt.Errorf("no external DHCP client found (tried: %s)", strings.Join(externalClients, ", "))
	}
	if !executor.CommandExists(client) {
		return fmt.Errorf("DHCP client %q not found in PATH", client)
	}

	_ = stopExternal(iface)

	_ = os.MkdirAll(pidDir, 0755)
	pidFile := filepath.Join(pidDir, iface+".ext.pid")

	var err error
	switch client {
	case "dhclient":
		_, err = executor.Run("dhclient", "-pf", pidFile, "-lf",
			filepath.Join(pidDir, iface+".lease"), iface)
	case "dhcpcd":
		_, err = executor.Run("dhcpcd", "--nobackground", "-1", iface)
	case "udhcpc":
		_, err = executor.Run("udhcpc", "-i", iface, "-p", pidFile, "-b")
	default:
		return fmt.Errorf("unsupported DHCP client: %s", client)
	}

	return err
}

func stopExternal(iface string) error {
	pidFile := filepath.Join(pidDir, iface+".ext.pid")
	data, err := os.ReadFile(pidFile)
	if err != nil {
		// Try legacy pid file location
		data, err = os.ReadFile(filepath.Join(pidDir, iface+".pid"))
	}
	if err != nil {
		data, err = os.ReadFile("/run/dhclient." + iface + ".pid")
	}
	if err != nil {
		// Brute-force release
		if executor.CommandExists("dhclient") {
			_, _ = executor.Run("dhclient", "-r", iface)
		}
		if executor.CommandExists("dhcpcd") {
			_, _ = executor.Run("dhcpcd", "-k", iface)
		}
		return nil
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	_ = proc.Signal(syscall.SIGTERM)
	_ = os.Remove(pidFile)

	return nil
}

func stopAllExternal() {
	entries, err := os.ReadDir(pidDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".ext.pid") || strings.HasSuffix(name, ".pid") {
			iface := strings.TrimSuffix(strings.TrimSuffix(name, ".ext.pid"), ".pid")
			_ = stopExternal(iface)
		}
	}
}

func statusExternal(iface string) string {
	pidFile := filepath.Join(pidDir, iface+".ext.pid")
	data, err := os.ReadFile(pidFile)
	if err != nil {
		data, err = os.ReadFile(filepath.Join(pidDir, iface+".pid"))
	}
	if err != nil {
		return ""
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return ""
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return ""
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return ""
	}
	return fmt.Sprintf("running (pid %d)", pid)
}
