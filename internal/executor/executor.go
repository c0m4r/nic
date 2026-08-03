package executor

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

var (
	DryRun  bool
	Verbose bool
)

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
	cmd := exec.Command(name, args...)
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
	cmd := exec.Command(name, args...)
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
