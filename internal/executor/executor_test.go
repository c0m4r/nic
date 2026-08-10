package executor

import (
	"context"
	"testing"
	"time"
)

func TestRunObservesCommandContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	restore := UseCommandContext(ctx)
	t.Cleanup(restore)

	result := make(chan error, 1)
	go func() {
		_, err := Run("/bin/sleep", "30")
		result <- err
	}()
	time.Sleep(25 * time.Millisecond)
	cancel()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled command unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled command did not stop")
	}

	restore()
	if _, err := Run("/bin/true"); err != nil {
		t.Fatalf("restored command context remained cancelled: %v", err)
	}
}

func TestCommandContextScopesRestoreOutOfOrder(t *testing.T) {
	first, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	second, cancelSecond := context.WithCancel(context.Background())
	defer cancelSecond()
	restoreFirst := UseCommandContext(first)
	restoreSecond := UseCommandContext(second)

	restoreFirst()
	if CommandContext() != second {
		t.Fatal("restoring an older scope replaced the active newer context")
	}
	restoreSecond()
	if CommandContext().Done() != nil {
		t.Fatal("out-of-order scopes did not restore the background context")
	}
}
