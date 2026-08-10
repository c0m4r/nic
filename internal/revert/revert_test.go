package revert

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/c0m4r/nic/internal/control"
)

func useTempRunDir(t *testing.T) {
	t.Helper()
	original := runDir
	runDir = t.TempDir()
	t.Cleanup(func() { runDir = original })
}

func TestConfirmRemovesPendingState(t *testing.T) {
	useTempRunDir(t)
	if err := os.WriteFile(stateFilePath(), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(revertConfigPath(), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := Confirm(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{stateFilePath(), revertConfigPath(), confirmFilePath()} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s was not removed", filepath.Base(path))
		}
	}
}

func TestConfirmRefusesOnceRevertOwnsLock(t *testing.T) {
	useTempRunDir(t)
	if err := os.WriteFile(stateFilePath(), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireLock(false)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseLock(lock)

	err = Confirm()
	if err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("Confirm() error = %v, want already in progress", err)
	}
}

func TestArmAndCancelPendingRevert(t *testing.T) {
	useTempRunDir(t)
	if err := os.WriteFile(stateFilePath(), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Arm(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(armFilePath()); err != nil {
		t.Fatalf("arm marker: %v", err)
	}
	if err := Cancel(); err != nil {
		t.Fatal(err)
	}
	if IsPending() {
		t.Fatal("pending revert remained after cancellation")
	}
}

func TestStopWatcherTerminatesOwnedProcess(t *testing.T) {
	useTempRunDir(t)
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	record, err := control.RecordForPID(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.WriteJSONAtomic(watcherPidPath(), record, 0600); err != nil {
		t.Fatal(err)
	}
	go func() { _ = cmd.Wait() }()

	if err := stopWatcher(); err != nil {
		t.Fatal(err)
	}
	if control.ProcessRecordIsLive(record) {
		t.Fatal("watcher process is still live")
	}
}

func TestWatcherRestoresImmediatelyWhenParentDiesBeforeArming(t *testing.T) {
	useTempRunDir(t)
	if err := os.WriteFile(stateFilePath(), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	original := restoreSnapshotForWatcher
	restoreSnapshotForWatcher = func(path string) error {
		if path != stateFilePath() {
			t.Fatalf("restore path = %q, want %q", path, stateFilePath())
		}
		called = true
		return nil
	}
	t.Cleanup(func() { restoreSnapshotForWatcher = original })

	started := time.Now()
	WatchAndRevert([]string{stateFilePath(), "60", strconv.Itoa(99999999), "not-a-live-start-time"})
	if !called {
		t.Fatal("watcher did not restore after its unarmed parent disappeared")
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("unarmed parent restore took %s instead of running immediately", elapsed)
	}
	if IsPending() {
		t.Fatal("pending revert state remained after restoration")
	}
}
