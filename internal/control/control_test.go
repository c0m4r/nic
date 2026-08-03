package control

import (
	"os"
	"path/filepath"
	"testing"
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
