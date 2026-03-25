package executor

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

var (
	DryRun  bool
	Verbose bool
)

func Run(name string, args ...string) (string, error) {
	if DryRun {
		fmt.Printf("[dry-run] %s %s\n", name, strings.Join(args, " "))
		return "", nil
	}
	if Verbose {
		fmt.Printf("+ %s %s\n", name, strings.Join(args, " "))
	}
	cmd := exec.Command(name, args...)
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
	if DryRun {
		return ""
	}
	cmd := exec.Command(name, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	_ = cmd.Run()
	return strings.TrimSpace(stdout.String())
}

func CommandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
