package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	DryRun  bool
	Verbose bool

	contextMu     sync.RWMutex
	contextScopes []commandContextScope
	nextContextID uint64
)

type commandContextScope struct {
	id  uint64
	ctx context.Context
}

// UseCommandContext makes subsequently started commands observe ctx. The
// returned function restores the previous context unless a newer caller has
// already replaced it. This lets the daemon cancel a slow startup command
// without also cancelling the rollback commands that follow it.
func UseCommandContext(ctx context.Context) func() {
	if ctx == nil {
		ctx = context.Background()
	}
	contextMu.Lock()
	nextContextID++
	id := nextContextID
	contextScopes = append(contextScopes, commandContextScope{id: id, ctx: ctx})
	contextMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			contextMu.Lock()
			defer contextMu.Unlock()
			for i := range contextScopes {
				if contextScopes[i].id == id {
					contextScopes[i].ctx = nil
					break
				}
			}
			for len(contextScopes) > 0 && contextScopes[len(contextScopes)-1].ctx == nil {
				contextScopes = contextScopes[:len(contextScopes)-1]
			}
		})
	}
}

// CommandContext returns the context used for new commands and long-running
// native operations started by the current reconciliation.
func CommandContext() context.Context {
	contextMu.RLock()
	defer contextMu.RUnlock()
	if len(contextScopes) == 0 {
		return context.Background()
	}
	return contextScopes[len(contextScopes)-1].ctx
}

func newCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(CommandContext(), name, args...)
	// Commands may be wrapper scripts that spawn children. Put each command in
	// its own process group so context cancellation cannot leave a child holding
	// stdout/stderr pipes open and blocking Cmd.Wait.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			if err == syscall.ESRCH {
				return os.ErrProcessDone
			}
			return err
		}
		return nil
	}
	cmd.WaitDelay = time.Second
	return cmd
}

func Run(name string, args ...string) (string, error) {
	return run(name, nil, args...)
}

// RunWithInput keeps sensitive input out of argv, verbose logs, and errors.
func RunWithInput(name, input string, args ...string) (string, error) {
	return run(name, strings.NewReader(input), args...)
}

func run(name string, stdin io.Reader, args ...string) (string, error) {
	if DryRun {
		fmt.Printf("[dry-run] %s %s\n", name, strings.Join(args, " "))
		return "", nil
	}
	if Verbose {
		fmt.Printf("+ %s %s\n", name, strings.Join(args, " "))
	}
	cmd := newCommand(name, args...)
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		return stdout.String(), fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), errMsg)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func RunIP(args ...string) (string, error) {
	return Run("ip", args...)
}

// RunSilent runs a command but does not print in verbose mode and ignores errors.
func RunSilent(name string, args ...string) string {
	output, _ := RunQuiet(name, args...)
	return output
}

// RunQuiet captures output and errors without honoring Verbose.
func RunQuiet(name string, args ...string) (string, error) {
	if DryRun {
		return "", nil
	}
	cmd := newCommand(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return strings.TrimSpace(stdout.String()), fmt.Errorf("%s: %s", name, message)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func CommandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
