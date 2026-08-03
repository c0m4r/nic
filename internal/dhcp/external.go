package dhcp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/c0m4r/nic/internal/control"
	"github.com/c0m4r/nic/internal/executor"
)

var externalClients = []string{"dhclient", "dhcpcd", "udhcpc"}

type externalRecord struct {
	Client  string             `json:"client"`
	Process *control.PIDRecord `json:"process,omitempty"`
}

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

	if err := stopExternal(iface); err != nil {
		return fmt.Errorf("stop previous external DHCP client: %w", err)
	}

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
	if err != nil {
		return err
	}

	record := externalRecord{Client: client}
	if data, readErr := os.ReadFile(pidFile); readErr == nil {
		if pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data))); parseErr == nil && pid > 0 {
			if process, recordErr := control.RecordForPID(pid); recordErr == nil {
				record.Process = &process
			}
		}
	}
	if err := control.WriteJSONAtomic(externalRecordPath(iface), record, 0600); err != nil {
		return fmt.Errorf("record external DHCP client: %w", err)
	}
	return nil
}

func stopExternal(iface string) error {
	var managed externalRecord
	recordErr := control.ReadJSON(externalRecordPath(iface), &managed)
	pidFile := filepath.Join(pidDir, iface+".ext.pid")
	usedPIDFile := pidFile
	data, err := os.ReadFile(pidFile)
	if err != nil {
		// Try legacy pid file location
		usedPIDFile = filepath.Join(pidDir, iface+".pid")
		data, err = os.ReadFile(usedPIDFile)
	}
	if err != nil {
		usedPIDFile = "/run/dhclient." + iface + ".pid"
		data, err = os.ReadFile(usedPIDFile)
	}
	if err != nil {
		if recordErr == nil && managed.Process != nil {
			signalErr := control.SignalProcessRecord(*managed.Process, syscall.SIGTERM)
			if errors.Is(signalErr, control.ErrNotRunning) {
				signalErr = nil
			}
			_ = os.Remove(externalRecordPath(iface))
			return signalErr
		}
		if recordErr == nil && managed.Client == "dhcpcd" && executor.CommandExists("dhcpcd") {
			_, err = executor.Run("dhcpcd", "-k", iface)
			_ = os.Remove(externalRecordPath(iface))
			return err
		}
		return nil
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return nil
	}

	allowed := managed.Client
	if allowed == "" {
		allowed, _ = control.ProcessExecutableName(pid)
		if !isExternalClient(allowed) {
			return fmt.Errorf("refusing to signal unrecognized process %d from %s", pid, usedPIDFile)
		}
	}
	if managed.Process != nil && managed.Process.PID == pid {
		if err := control.SignalProcessRecord(*managed.Process, syscall.SIGTERM); err != nil && !errors.Is(err, control.ErrNotRunning) {
			return err
		}
	} else if name, nameErr := control.ProcessExecutableName(pid); nameErr == nil && name == allowed {
		proc, findErr := os.FindProcess(pid)
		if findErr == nil {
			_ = proc.Signal(syscall.SIGTERM)
		}
	}
	_ = os.Remove(usedPIDFile)
	_ = os.Remove(externalRecordPath(iface))

	return nil
}

func stopAllExternal() error {
	entries, err := os.ReadDir(pidDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var stopErrors []error
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".external.json") {
			iface := strings.TrimSuffix(name, ".external.json")
			if err := stopExternal(iface); err != nil {
				stopErrors = append(stopErrors, err)
			}
		} else if strings.HasSuffix(name, ".ext.pid") || strings.HasSuffix(name, ".pid") {
			iface := strings.TrimSuffix(strings.TrimSuffix(name, ".ext.pid"), ".pid")
			if err := stopExternal(iface); err != nil {
				stopErrors = append(stopErrors, err)
			}
		}
	}
	return errors.Join(stopErrors...)
}

func externalRecordPath(iface string) string {
	return filepath.Join(pidDir, iface+".external.json")
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
