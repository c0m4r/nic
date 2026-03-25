package revert

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/c0m4r/nic/internal/state"
)

const (
	runDir      = "/run/nic"
	stateFile   = "revert-state.json"
	confirmFile = "confirmed"
	watcherPid  = "revert-watcher.pid"
)

func stateFilePath() string {
	return filepath.Join(runDir, stateFile)
}

func confirmFilePath() string {
	return filepath.Join(runDir, confirmFile)
}

func watcherPidPath() string {
	return filepath.Join(runDir, watcherPid)
}

// SaveAndStartWatcher saves the current network state and starts a background
// watcher process that will revert changes if not confirmed within timeout seconds.
// The watcher runs in its own session (TTY-independent).
func SaveAndStartWatcher(nicBinary string, timeoutSecs int) error {
	_ = os.MkdirAll(runDir, 0755)

	// Remove any previous confirm signal
	_ = os.Remove(confirmFilePath())

	// Save current state
	if err := state.SaveState(stateFilePath()); err != nil {
		return fmt.Errorf("save state: %w", err)
	}

	// Start watcher as a background process in its own session
	cmd := exec.Command(nicBinary, "__revert-watcher",
		stateFilePath(), strconv.Itoa(timeoutSecs))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start revert watcher: %w", err)
	}

	// Save watcher PID
	_ = os.WriteFile(watcherPidPath(),
		[]byte(strconv.Itoa(cmd.Process.Pid)), 0644)

	// Detach — don't wait for it
	_ = cmd.Process.Release()

	return nil
}

// Confirm signals the revert watcher that changes are accepted.
func Confirm() error {
	// Check if there's a pending revert
	if _, err := os.Stat(stateFilePath()); os.IsNotExist(err) {
		return fmt.Errorf("no pending changes to confirm")
	}

	// Create confirm signal
	if err := os.WriteFile(confirmFilePath(), []byte("ok"), 0644); err != nil {
		return fmt.Errorf("write confirm: %w", err)
	}

	// Clean up
	_ = os.Remove(stateFilePath())

	// Kill watcher
	killWatcher()

	return nil
}

// IsPending returns true if there's a pending revert.
func IsPending() bool {
	_, err := os.Stat(stateFilePath())
	return err == nil
}

func killWatcher() {
	data, err := os.ReadFile(watcherPidPath())
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = proc.Signal(syscall.SIGTERM)
	_ = os.Remove(watcherPidPath())
}

// WatchAndRevert is the internal command run by the background watcher process.
// args: [stateFilePath, timeoutSecs]
func WatchAndRevert(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "revert-watcher: missing arguments")
		os.Exit(1)
	}

	statePath := args[0]
	timeout, err := strconv.Atoi(args[1])
	if err != nil || timeout <= 0 {
		timeout = 10
	}

	deadline := time.Now().Add(time.Duration(timeout) * time.Second)

	for time.Now().Before(deadline) {
		// Check for confirm signal
		if _, err := os.Stat(confirmFilePath()); err == nil {
			// Confirmed — clean up and exit
			_ = os.Remove(confirmFilePath())
			_ = os.Remove(statePath)
			_ = os.Remove(watcherPidPath())
			os.Exit(0)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Timeout reached — revert
	fmt.Fprintln(os.Stderr, "nic: revert timeout reached, restoring previous network state...")

	if err := state.RestoreState(statePath); err != nil {
		fmt.Fprintf(os.Stderr, "nic: revert failed: %v\n", err)
		os.Exit(1)
	}

	// Clean up
	_ = os.Remove(statePath)
	_ = os.Remove(confirmFilePath())
	_ = os.Remove(watcherPidPath())

	fmt.Fprintln(os.Stderr, "nic: network state reverted successfully")
}
