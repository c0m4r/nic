package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	RunDir             = "/run/nic"
	PIDPath            = RunDir + "/nic.pid"
	AppliedConfigPath  = RunDir + "/applied-config.json"
	PendingConfigPath  = RunDir + "/pending-config.json"
	BaseStatePath      = RunDir + "/base-state.json"
	ReloadRequestPath  = RunDir + "/reload-request.json"
	ReloadResponsePath = RunDir + "/reload-response.json"
	RevertResponsePath = RunDir + "/revert-response.json"
)

var ErrNotRunning = errors.New("nic daemon is not running")

type PIDRecord struct {
	PID       int    `json:"pid"`
	StartTime string `json:"start_time"`
}

type ReloadRequest struct {
	ID         string `json:"id"`
	ConfigPath string `json:"config_path"`
	Timeout    int    `json:"timeout"`
}

type Response struct {
	ID    string `json:"id,omitempty"`
	Error string `json:"error,omitempty"`
}

func RecordForPID(pid int) (PIDRecord, error) {
	start, err := processStartTime(pid)
	if err != nil {
		return PIDRecord{}, err
	}
	return PIDRecord{PID: pid, StartTime: start}, nil
}

func ReadProcessRecord(path string) (PIDRecord, error) {
	var record PIDRecord
	if err := ReadJSON(path, &record); err != nil {
		return PIDRecord{}, err
	}
	if record.PID <= 0 || record.StartTime == "" {
		return PIDRecord{}, fmt.Errorf("invalid process record")
	}
	return record, nil
}

func ProcessRecordIsLive(record PIDRecord) bool {
	return recordIsLive(record)
}

func SignalProcessRecord(record PIDRecord, sig syscall.Signal) error {
	if !recordIsLive(record) {
		return ErrNotRunning
	}
	proc, err := os.FindProcess(record.PID)
	if err != nil {
		return ErrNotRunning
	}
	return proc.Signal(sig)
}

func ProcessExecutableName(pid int) (string, error) {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(filepath.Base(exe), " (deleted)"), nil
}

// ClaimDaemon atomically claims the daemon PID file. Stale records are
// removed only after the recorded process start time no longer matches.
func ClaimDaemon() (func(), error) {
	if err := os.MkdirAll(RunDir, 0755); err != nil {
		return nil, err
	}

	record, err := currentPIDRecord()
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')

	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(PIDPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			if _, writeErr := f.Write(data); writeErr != nil {
				_ = f.Close()
				_ = os.Remove(PIDPath)
				return nil, writeErr
			}
			if closeErr := f.Close(); closeErr != nil {
				_ = os.Remove(PIDPath)
				return nil, closeErr
			}
			return func() { removeIfOwned(record) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}

		existing, readErr := readPIDRecord()
		if readErr == nil && recordIsLive(existing) {
			return nil, fmt.Errorf("nic daemon already running with pid %d", existing.PID)
		}
		if removeErr := os.Remove(PIDPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return nil, fmt.Errorf("remove stale pid file: %w", removeErr)
		}
	}

	return nil, fmt.Errorf("could not claim daemon pid file")
}

func IsDaemonRunning() bool {
	record, err := readPIDRecord()
	return err == nil && recordIsLive(record)
}

func SignalDaemon(sig syscall.Signal) error {
	record, err := readPIDRecord()
	if err != nil || !recordIsLive(record) {
		return ErrNotRunning
	}
	proc, err := os.FindProcess(record.PID)
	if err != nil {
		return ErrNotRunning
	}
	if err := proc.Signal(sig); err != nil {
		if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
			return ErrNotRunning
		}
		return err
	}
	return nil
}

func StopDaemon(timeout time.Duration) (bool, error) {
	if err := SignalDaemon(syscall.SIGTERM); err != nil {
		if errors.Is(err, ErrNotRunning) {
			return false, nil
		}
		return false, err
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !IsDaemonRunning() {
			return true, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return true, fmt.Errorf("timed out waiting for nic daemon to stop")
}

func WriteJSONAtomic(path string, value any, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	f, err := os.CreateTemp(filepath.Dir(path), ".nic-tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	removeTmp := true
	defer func() {
		_ = f.Close()
		if removeTmp {
			_ = os.Remove(tmp)
		}
	}()

	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	removeTmp = false
	return nil
}

func ReadJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func WaitResponse(path, id string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var response Response
		if err := ReadJSON(path, &response); err == nil && response.ID == id {
			_ = os.Remove(path)
			if response.Error != "" {
				return errors.New(response.Error)
			}
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for daemon response")
}

func NewRequestID() string {
	return fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
}

func currentPIDRecord() (PIDRecord, error) {
	pid := os.Getpid()
	start, err := processStartTime(pid)
	if err != nil {
		return PIDRecord{}, err
	}
	return PIDRecord{PID: pid, StartTime: start}, nil
}

func readPIDRecord() (PIDRecord, error) {
	data, err := os.ReadFile(PIDPath)
	if err != nil {
		return PIDRecord{}, err
	}
	var record PIDRecord
	if err := json.Unmarshal(data, &record); err == nil && record.PID > 0 && record.StartTime != "" {
		return record, nil
	}

	// Accept the legacy single-PID format only when the executable name is nic.
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return PIDRecord{}, fmt.Errorf("invalid daemon pid file")
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || !strings.HasPrefix(filepath.Base(exe), "nic") {
		return PIDRecord{}, ErrNotRunning
	}
	start, err := processStartTime(pid)
	if err != nil {
		return PIDRecord{}, err
	}
	return PIDRecord{PID: pid, StartTime: start}, nil
}

func recordIsLive(record PIDRecord) bool {
	if record.PID <= 0 || record.StartTime == "" {
		return false
	}
	start, err := processStartTime(record.PID)
	return err == nil && start == record.StartTime
}

func processStartTime(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	// The second field is parenthesized and may itself contain spaces.
	end := strings.LastIndexByte(string(data), ')')
	if end == -1 || end+2 >= len(data) {
		return "", fmt.Errorf("invalid /proc/%d/stat", pid)
	}
	fields := strings.Fields(string(data[end+2:]))
	// fields starts at field 3; process start time is field 22.
	if len(fields) <= 19 {
		return "", fmt.Errorf("invalid /proc/%d/stat", pid)
	}
	return fields[19], nil
}

func removeIfOwned(record PIDRecord) {
	existing, err := readPIDRecord()
	if err == nil && existing == record {
		_ = os.Remove(PIDPath)
	}
}
