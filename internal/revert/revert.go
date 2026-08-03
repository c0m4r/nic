package revert

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/c0m4r/nic/internal/control"
	"github.com/c0m4r/nic/internal/state"
)

var runDir = "/run/nic"

const (
	stateFile    = "revert-state.json"
	confirmFile  = "confirmed"
	watcherPid   = "revert-watcher.pid"
	revertConfig = "revert-config.json"
	lockFile     = "revert.lock"
	armFile      = "revert-armed"
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

func revertConfigPath() string {
	return filepath.Join(runDir, revertConfig)
}

func lockFilePath() string {
	return filepath.Join(runDir, lockFile)
}

func armFilePath() string {
	return filepath.Join(runDir, armFile)
}

func PendingStatePath() string { return stateFilePath() }

func SavedConfigPath() string { return revertConfigPath() }

// SaveAndStartWatcher captures the current state and starts an unarmed watcher.
// Arm must be called after the new configuration has been applied successfully;
// until then, the watcher restores the snapshot only if this process dies.
func SaveAndStartWatcher(nicBinary string, timeoutSecs int) error {
	lock, err := acquireLock(false)
	if err != nil {
		return fmt.Errorf("lock pending revert: %w", err)
	}
	defer releaseLock(lock)

	if IsPending() {
		return fmt.Errorf("a network revert is already pending; run 'nic confirm' first")
	}
	if err := stopWatcher(); err != nil {
		return fmt.Errorf("stop stale revert watcher: %w", err)
	}
	cleanupPendingFiles()
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return err
	}

	// Remove any previous confirm signal
	_ = os.Remove(confirmFilePath())
	_ = os.Remove(armFilePath())

	// Save current state
	if err := state.SaveState(stateFilePath()); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	if data, err := os.ReadFile(control.AppliedConfigPath); err == nil {
		if err := os.WriteFile(revertConfigPath(), data, 0600); err != nil {
			_ = os.Remove(stateFilePath())
			return fmt.Errorf("save applied configuration: %w", err)
		}
	} else if !os.IsNotExist(err) {
		_ = os.Remove(stateFilePath())
		return fmt.Errorf("read applied configuration: %w", err)
	}

	// Start watcher as a background process in its own session
	parent, err := control.RecordForPID(os.Getpid())
	if err != nil {
		cleanupPendingFiles()
		return fmt.Errorf("record applying process: %w", err)
	}
	cmd := exec.Command(nicBinary, "__revert-watcher",
		stateFilePath(), strconv.Itoa(timeoutSecs), strconv.Itoa(parent.PID), parent.StartTime)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		_ = os.Remove(stateFilePath())
		_ = os.Remove(revertConfigPath())
		return fmt.Errorf("start revert watcher: %w", err)
	}

	// Save watcher PID
	record, recordErr := control.RecordForPID(cmd.Process.Pid)
	if recordErr != nil {
		_ = cmd.Process.Kill()
		_ = os.Remove(stateFilePath())
		_ = os.Remove(revertConfigPath())
		return fmt.Errorf("record revert watcher: %w", recordErr)
	}
	if err := control.WriteJSONAtomic(watcherPidPath(), record, 0600); err != nil {
		_ = cmd.Process.Kill()
		_ = os.Remove(stateFilePath())
		_ = os.Remove(revertConfigPath())
		return fmt.Errorf("save revert watcher pid: %w", err)
	}

	// Reap the watcher asynchronously while this process remains alive. The
	// watcher is in its own session and continues independently if we exit.
	go func() { _ = cmd.Wait() }()

	return nil
}

// Arm starts the confirmation timeout after a successful apply.
func Arm() error {
	if !IsPending() {
		return fmt.Errorf("no pending changes to arm")
	}
	if err := os.WriteFile(armFilePath(), []byte("armed\n"), 0600); err != nil {
		return fmt.Errorf("arm revert watcher: %w", err)
	}
	return nil
}

// Cancel discards a pending snapshot after an apply failed and restored its
// predecessor itself.
func Cancel() error {
	lock, err := acquireLock(true)
	if err != nil {
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return fmt.Errorf("network revert is already in progress")
		}
		return fmt.Errorf("lock pending revert: %w", err)
	}
	defer releaseLock(lock)
	if err := stopWatcher(); err != nil {
		return err
	}
	cleanupPendingFiles()
	return nil
}

// Confirm signals the revert watcher that changes are accepted.
func Confirm() error {
	lock, err := acquireLock(true)
	if err != nil {
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return fmt.Errorf("network revert is already in progress")
		}
		return fmt.Errorf("lock pending revert: %w", err)
	}
	defer releaseLock(lock)

	// Check if there's a pending revert
	if _, err := os.Stat(stateFilePath()); os.IsNotExist(err) {
		return fmt.Errorf("no pending changes to confirm")
	} else if err != nil {
		return fmt.Errorf("check pending revert: %w", err)
	}

	// Create confirm signal
	if err := os.WriteFile(confirmFilePath(), []byte("ok"), 0644); err != nil {
		return fmt.Errorf("write confirm: %w", err)
	}

	// Kill watcher
	if err := stopWatcher(); err != nil {
		// Leave the confirmation marker in place so a watcher that could not be
		// signaled still observes the accepted configuration and exits.
		return fmt.Errorf("stop revert watcher: %w", err)
	}

	// Clean up after the watcher has been signaled.
	cleanupPendingFiles()

	return nil
}

// IsPending returns true if there's a pending revert.
func IsPending() bool {
	_, err := os.Stat(stateFilePath())
	return err == nil
}

func stopWatcher() error {
	record, err := control.ReadProcessRecord(watcherPidPath())
	if err != nil {
		_ = os.Remove(watcherPidPath())
		return nil
	}
	if err := control.SignalProcessRecord(record, syscall.SIGTERM); err != nil && err != control.ErrNotRunning {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	for control.ProcessRecordIsLive(record) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if control.ProcessRecordIsLive(record) {
		return fmt.Errorf("timed out waiting for revert watcher %d", record.PID)
	}
	_ = os.Remove(watcherPidPath())
	return nil
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

	// New watchers stay unarmed while configuration is being applied. If the
	// applying process disappears before arming, restore immediately. Two-arg
	// invocation remains compatible with older internal callers.
	if len(args) >= 4 {
		parentPID, parseErr := strconv.Atoi(args[2])
		if parseErr != nil || parentPID <= 0 || args[3] == "" {
			fmt.Fprintln(os.Stderr, "revert-watcher: invalid parent process record")
			os.Exit(1)
		}
		parent := control.PIDRecord{PID: parentPID, StartTime: args[3]}
		for {
			if _, statErr := os.Stat(statePath); os.IsNotExist(statErr) {
				cleanupPendingFiles()
				return
			}
			if _, statErr := os.Stat(confirmFilePath()); statErr == nil {
				cleanupPendingFiles()
				return
			}
			if _, statErr := os.Stat(armFilePath()); statErr == nil {
				break
			}
			if !control.ProcessRecordIsLive(parent) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	deadline := time.Now().Add(time.Duration(timeout) * time.Second)

	for time.Now().Before(deadline) {
		if _, err := os.Stat(statePath); os.IsNotExist(err) {
			cleanupPendingFiles()
			return
		}
		// Check for confirm signal
		if _, err := os.Stat(confirmFilePath()); err == nil {
			// Confirmed — clean up and exit
			cleanupPendingFiles()
			os.Exit(0)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Serialize the deadline decision with Confirm. Once this lock is held,
	// confirmation either already removed the pending state or is too late.
	lock, err := acquireLock(false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nic: lock revert: %v\n", err)
		os.Exit(1)
	}
	defer releaseLock(lock)
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		cleanupPendingFiles()
		return
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "nic: check pending revert: %v\n", err)
		os.Exit(1)
	}

	// Check once more at the deadline so confirmation cannot be missed between
	// the loop condition and restoration.
	if _, err := os.Stat(confirmFilePath()); err == nil {
		cleanupPendingFiles()
		return
	}

	// Timeout reached — revert
	fmt.Fprintln(os.Stderr, "nic: revert timeout reached, restoring previous network state...")

	if err := restoreSnapshot(statePath); err != nil {
		fmt.Fprintf(os.Stderr, "nic: revert failed: %v\n", err)
		os.Exit(1)
	}

	// Clean up
	cleanupPendingFiles()

	fmt.Fprintln(os.Stderr, "nic: network state reverted successfully")
}

func cleanupPendingFiles() {
	_ = os.Remove(stateFilePath())
	_ = os.Remove(revertConfigPath())
	_ = os.Remove(confirmFilePath())
	_ = os.Remove(armFilePath())
	_ = os.Remove(watcherPidPath())
}

func acquireLock(nonblocking bool) (*os.File, error) {
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockFilePath(), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_EX
	if nonblocking {
		how |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func releaseLock(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

func restoreSnapshot(statePath string) error {
	if control.IsDaemonRunning() {
		_ = os.Remove(control.RevertResponsePath)
		if err := control.SignalDaemon(syscall.SIGUSR1); err != nil {
			return fmt.Errorf("signal daemon to revert: %w", err)
		}
		if err := control.WaitResponse(control.RevertResponsePath, "revert", 90*time.Second); err != nil {
			return fmt.Errorf("daemon revert: %w", err)
		}
		return nil
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "__restore-snapshot", statePath, revertConfigPath())
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("restore helper: %w: %s", err, strings.TrimSpace(output.String()))
	}
	return nil
}
