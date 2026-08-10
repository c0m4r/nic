package dhcp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/c0m4r/nic/internal/control"
	"github.com/c0m4r/nic/internal/executor"
)

var externalClients = []string{"dhclient", "dhcpcd", "udhcpc"}

const externalStopTimeout = 5 * time.Second

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
	if recordErr != nil && !os.IsNotExist(recordErr) {
		return fmt.Errorf("read external DHCP record: %w", recordErr)
	}
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
			if err := stopTrackedExternal(managed); err != nil {
				return err
			}
			_ = os.Remove(externalRecordPath(iface))
			return nil
		}
		if recordErr == nil && managed.Client == "dhcpcd" && executor.CommandExists("dhcpcd") {
			_, err = executor.Run("dhcpcd", "-k", iface)
			if err == nil {
				_ = os.Remove(externalRecordPath(iface))
			}
			return err
		}
		if recordErr == nil && managed.Client != "" {
			return fmt.Errorf("cannot verify external DHCP client %q on %s without a PID record", managed.Client, iface)
		}
		return nil
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("invalid external DHCP PID in %s", usedPIDFile)
	}

	if managed.Process != nil && managed.Process.PID != pid {
		return fmt.Errorf("external DHCP PID record mismatch for %s", iface)
	}

	if managed.Process != nil && managed.Process.PID == pid {
		if err := stopTrackedExternal(managed); err != nil {
			return err
		}
	} else {
		name, nameErr := control.ProcessExecutableName(pid)
		if errors.Is(nameErr, os.ErrNotExist) {
			_ = os.Remove(usedPIDFile)
			_ = os.Remove(externalRecordPath(iface))
			return nil
		}
		if nameErr != nil {
			return fmt.Errorf("inspect external DHCP process %d: %w", pid, nameErr)
		}
		if !isExternalClient(name) || (managed.Client != "" && name != managed.Client) {
			return fmt.Errorf("refusing to signal unrecognized process %d from %s", pid, usedPIDFile)
		}
		process, err := control.RecordForPID(pid)
		if err != nil {
			return fmt.Errorf("record external DHCP process %d: %w", pid, err)
		}
		if err := control.TerminateProcessRecord(process, syscall.SIGTERM, externalStopTimeout); err != nil {
			return err
		}
	}
	_ = os.Remove(usedPIDFile)
	_ = os.Remove(externalRecordPath(iface))

	return nil
}

func stopTrackedExternal(managed externalRecord) error {
	if managed.Process == nil {
		return nil
	}
	if managed.Client != "" && !isExternalClient(managed.Client) {
		return fmt.Errorf("refusing to signal unrecognized external DHCP client %q", managed.Client)
	}
	if control.ProcessRecordIsLive(*managed.Process) {
		name, err := control.ProcessExecutableName(managed.Process.PID)
		if err != nil {
			return fmt.Errorf("inspect external DHCP process %d: %w", managed.Process.PID, err)
		}
		if !isExternalClient(name) || (managed.Client != "" && name != managed.Client) {
			return fmt.Errorf("refusing to signal unrecognized process %d", managed.Process.PID)
		}
	}
	return control.TerminateProcessRecord(*managed.Process, syscall.SIGTERM, externalStopTimeout)
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
