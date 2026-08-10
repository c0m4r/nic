package control

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestProcessRecordTracksStartTime(t *testing.T) {
	record, err := RecordForPID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !ProcessRecordIsLive(record) {
		t.Fatal("current process record should be live")
	}
	record.StartTime = "wrong"
	if ProcessRecordIsLive(record) {
		t.Fatal("mismatched start time should be rejected")
	}
}

func TestJSONAtomicRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	want := Response{ID: "one", Error: "failure"}
	if err := WriteJSONAtomic(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	var got Response
	if err := ReadJSON(path, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
}

func TestTerminateProcessRecordWaitsForExit(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	go func() { _ = cmd.Wait() }()

	record, err := RecordForPID(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := TerminateProcessRecord(record, syscall.SIGTERM, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if ProcessRecordIsLive(record) {
		t.Fatal("process remained live after TerminateProcessRecord")
	}
}

func TestClaimReloadSerializesRequests(t *testing.T) {
	originalRunDir := RunDir
	originalLockPath := ReloadLockPath
	RunDir = t.TempDir()
	ReloadLockPath = filepath.Join(RunDir, "reload.lock")
	t.Cleanup(func() {
		RunDir = originalRunDir
		ReloadLockPath = originalLockPath
	})

	release, err := ClaimReload()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClaimReload(); !errors.Is(err, ErrReloadInProgress) {
		t.Fatalf("second ClaimReload error = %v, want ErrReloadInProgress", err)
	}
	release()
	release, err = ClaimReload()
	if err != nil {
		t.Fatal(err)
	}
	release()
}
