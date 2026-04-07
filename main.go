package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/c0m4r/nic/internal/alias"
	"github.com/c0m4r/nic/internal/color"
	"github.com/c0m4r/nic/internal/config"
	"github.com/c0m4r/nic/internal/dhcp"
	"github.com/c0m4r/nic/internal/dns"
	"github.com/c0m4r/nic/internal/executor"
	"github.com/c0m4r/nic/internal/revert"
	"github.com/c0m4r/nic/internal/state"
	"github.com/c0m4r/nic/internal/wifi"
)

var version = "0.1.0"

const defaultConfig = "/etc/nic.conf"

func main() {
	args := os.Args[1:]
	configPath := defaultConfig

	// Extract global flags
	var filtered []string
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--config="):
			configPath = strings.TrimPrefix(arg, "--config=")
		case arg == "--verbose" || arg == "-v":
			executor.Verbose = true
		case arg == "--help" || arg == "-h":
			printUsage()
			return
		case arg == "--version" || arg == "-V":
			fmt.Printf("nic %s\n", version)
			return
		default:
			filtered = append(filtered, arg)
		}
	}
	args = filtered

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	cmd := args[0]
	cmdArgs := args[1:]

	switch cmd {
	case "start":
		daemonMode := false
		for _, arg := range cmdArgs {
			if arg == "--daemon" || arg == "-d" {
				daemonMode = true
			}
		}
		fmt.Printf("Starting nic v%s...\n", version)
		if err := cmdStart(configPath, daemonMode); err != nil {
			fatal(err)
		}
	case "stop":
		fmt.Printf("Stopping nic v%s...\n", version)
		if err := cmdStop(configPath, cmdArgs); err != nil {
			fatal(err)
		}
	case "restart":
		fmt.Printf("Restarting nic v%s...\n", version)
		if err := cmdRestart(configPath, cmdArgs); err != nil {
			fatal(err)
		}
	case "reload":
		fmt.Printf("Reloading nic v%s...\n", version)
		if err := cmdReload(configPath, cmdArgs); err != nil {
			fatal(err)
		}
	case "status":
		cmdStatus()
	case "show":
		fmt.Printf("nic v%s | show\n", version)
		if err := cmdShow(configPath); err != nil {
			fatal(err)
		}
	case "dry-run":
		fmt.Printf("nic v%s | dry-run mode\n", version)
		if err := cmdDryRun(configPath); err != nil {
			fatal(err)
		}
	case "confirm":
		if err := cmdConfirm(); err != nil {
			fatal(err)
		}
	case "version":
		fmt.Printf("nic %s\n", version)
	case "__revert-watcher":
		revert.WatchAndRevert(cmdArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "%s %v\n", color.BoldRed("nic:"), err)
	os.Exit(1)
}

func printUsage() {
	fmt.Print(`nic - network interface configurator

Usage: nic <command> [options]

Commands:
  start                  Apply network configuration
  stop                   Tear down network configuration
  restart [options]      Stop and re-apply configuration
  reload  [options]      Re-apply configuration (shows diff)
  status                 Show current network state
  show                   Show parsed configuration
  dry-run                Show what would be done without applying
  confirm                Confirm changes after reload/restart with timeout
  version                Show version

Options:
  --config=PATH          Config file path (default: /etc/nic.conf)
  --verbose, -v          Show commands being executed
  --confirm-timeout=N    Revert after N seconds if not confirmed (default: 10)
  --daemon, -d           Run in daemon mode (keeps DHCP clients running)
  --force                Skip confirmation prompts
  --help, -h             Show this help
  --version, -V          Show version
`)
}

// --- Command implementations ---

func cmdStart(configPath string, daemonMode bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := applyConfig(cfg, daemonMode); err != nil {
		return err
	}

	if daemonMode {
		// Write PID file for daemon mode
		if err := writePIDFile(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not write PID file: %v\n", err)
		}
		fmt.Println("Running in daemon mode. Press Ctrl+C to stop.")
		waitForShutdownSignal()
	}

	return nil
}

func applyConfig(cfg *config.Config, daemonMode bool) error {
	mgr := alias.NewManager()
	var nameservers []string

	// First pass: collect aliases and pins
	for _, cmd := range cfg.Commands {
		switch cmd.Type {
		case config.CmdAlias:
			mgr.AddAlias(cmd.Tokens[1], cmd.Tokens[2])
		case config.CmdPin:
			mgr.AddPin(cmd.Tokens[1], cmd.Tokens[2])
		}
	}

	// Resolve pins (look up actual interface names by MAC)
	if err := mgr.Resolve(); err != nil {
		return fmt.Errorf("resolve aliases: %w", err)
	}

	// Setup loopback
	setupLoopback()

	// Second pass: execute commands
	for _, cmd := range cfg.Commands {
		switch cmd.Type {
		case config.CmdAlias, config.CmdPin:
			// Already processed
			continue

		case config.CmdNameserver:
			nameservers = append(nameservers, cmd.Tokens[1])

		case config.CmdWifi:
			iface := ""
			if len(cmd.Tokens) >= 4 {
				iface = cmd.Tokens[3]
				if resolved, ok := mgr.Get(iface); ok {
					iface = resolved
				}
			}
			if err := wifi.Connect(cmd.Tokens[1], cmd.Tokens[2], iface); err != nil {
				return fmt.Errorf("%s:%d: %w", cmd.File, cmd.LineNum, err)
			}

		case config.CmdDHCP:
			iface := cmd.Tokens[1]
			if resolved, ok := mgr.Get(iface); ok {
				iface = resolved
			}
			client := ""
			if len(cmd.Tokens) >= 3 {
				client = cmd.Tokens[2]
			}
			if err := dhcp.Start(iface, client, daemonMode); err != nil {
				return fmt.Errorf("%s:%d: %w", cmd.File, cmd.LineNum, err)
			}

		case config.CmdDHCPv6:
			iface := cmd.Tokens[1]
			if resolved, ok := mgr.Get(iface); ok {
				iface = resolved
			}
			if err := dhcp.StartV6(iface, daemonMode); err != nil {
				return fmt.Errorf("%s:%d: %w", cmd.File, cmd.LineNum, err)
			}

		case config.CmdIPRoute2, config.CmdIfShortcut, config.CmdIPShortcut, config.CmdRouteShortcut:
			ipArgs := config.ExpandCommand(cmd)
			if ipArgs == nil {
				continue
			}
			// Resolve aliases in the ip arguments
			ipArgs = mgr.ResolveInTokens(ipArgs)
			if _, err := executor.RunIP(ipArgs...); err != nil {
				if isAlreadyExists(err) {
					if executor.Verbose {
						fmt.Printf("  (already exists, skipping)\n")
					}
					continue
				}
				return fmt.Errorf("%s:%d: %w", cmd.File, cmd.LineNum, err)
			}
		}
	}

	// Apply nameservers
	if len(nameservers) > 0 {
		if err := dns.WriteResolvConf(nameservers); err != nil {
			return fmt.Errorf("write resolv.conf: %w", err)
		}
		if err := dns.Guard(); err != nil {
			// Non-fatal, just warn
			fmt.Fprintf(os.Stderr, "warning: could not guard resolv.conf: %v\n", err)
		}
	}

	// Wait for IPv6 DAD (duplicate address detection) to complete
	waitForDAD()

	return nil
}

func cmdStop(configPath string, cmdArgs []string) error {
	force := false
	for _, arg := range cmdArgs {
		if arg == "--force" {
			force = true
		}
	}

	if !force {
		fmt.Print("This will tear down all network configuration. Continue? [y/N] ")
		if !confirm() {
			fmt.Println("Aborted.")
			return nil
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Stop DHCP clients (also cleans up addresses from disk leases)
	dhcp.StopAll()

	// Disconnect WiFi
	for _, cmd := range cfg.Commands {
		if cmd.Type == config.CmdWifi {
			iface := wifi.DetectInterface()
			if iface != "" {
				_ = wifi.Disconnect(iface)
			}
		}
	}

	mgr := alias.NewManager()
	for _, cmd := range cfg.Commands {
		switch cmd.Type {
		case config.CmdAlias:
			mgr.AddAlias(cmd.Tokens[1], cmd.Tokens[2])
		case config.CmdPin:
			mgr.AddPin(cmd.Tokens[1], cmd.Tokens[2])
		}
	}
	_ = mgr.Resolve()

	// Process commands in reverse to tear down
	for i := len(cfg.Commands) - 1; i >= 0; i-- {
		cmd := cfg.Commands[i]
		switch cmd.Type {
		case config.CmdIPRoute2, config.CmdIfShortcut, config.CmdIPShortcut, config.CmdRouteShortcut:
			ipArgs := config.ExpandCommand(cmd)
			if ipArgs == nil {
				continue
			}
			ipArgs = mgr.ResolveInTokens(ipArgs)
			reverseArgs := reverseIPCommand(ipArgs)
			if reverseArgs != nil {
				_, _ = executor.RunIP(reverseArgs...)
			}
		}
	}

	// Unguard resolv.conf
	_ = dns.Unguard()

	return nil
}

// reverseIPCommand generates the reverse of an ip command for teardown.
func reverseIPCommand(args []string) []string {
	if len(args) < 2 {
		return nil
	}

	obj := args[0]
	action := args[1]

	switch {
	case obj == "link" && action == "set":
		// ip link set <iface> up → ip link set <iface> down
		result := make([]string, len(args))
		copy(result, args)
		for i, a := range result {
			if a == "up" {
				result[i] = "down"
			}
		}
		return result

	case obj == "link" && action == "add":
		// ip link add <name> ... → ip link del <name>
		if len(args) >= 3 {
			return []string{"link", "del", args[2]}
		}

	case obj == "address" && action == "add":
		// ip address add ... → ip address del ...
		result := make([]string, len(args))
		copy(result, args)
		result[1] = "del"
		return result

	case obj == "route" && action == "add":
		// ip route add ... → ip route del ...
		result := make([]string, len(args))
		copy(result, args)
		result[1] = "del"
		return result
	}

	return nil
}

func cmdRestart(configPath string, cmdArgs []string) error {
	timeout := 0
	force := false

	for _, arg := range cmdArgs {
		switch {
		case strings.HasPrefix(arg, "--confirm-timeout="):
			v, err := strconv.Atoi(strings.TrimPrefix(arg, "--confirm-timeout="))
			if err != nil || v <= 0 {
				return fmt.Errorf("invalid --confirm-timeout value")
			}
			timeout = v
		case arg == "--confirm-timeout":
			timeout = 10
		case arg == "--force":
			force = true
		}
	}

	if !force {
		fmt.Print("This will restart all network configuration. Continue? [y/N] ")
		if !confirm() {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Save state and start watcher if timeout requested
	if timeout > 0 {
		selfBin, _ := os.Executable()
		if err := revert.SaveAndStartWatcher(selfBin, timeout); err != nil {
			return fmt.Errorf("setup revert: %w", err)
		}
	}

	// Stop (force — we already confirmed above)
	if err := cmdStop(configPath, []string{"--force"}); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning during stop: %v\n", err)
	}

	// Start
	if err := cmdStart(configPath, false); err != nil {
		return err
	}

	if timeout > 0 {
		fmt.Printf("\nNetwork reconfigured. Run 'nic confirm' within %ds to keep changes.\n", timeout)
	} else {
		fmt.Println("Network restarted.")
	}

	return nil
}

func cmdReload(configPath string, cmdArgs []string) error {
	timeout := 0
	force := false

	for _, arg := range cmdArgs {
		switch {
		case strings.HasPrefix(arg, "--confirm-timeout="):
			v, err := strconv.Atoi(strings.TrimPrefix(arg, "--confirm-timeout="))
			if err != nil || v <= 0 {
				return fmt.Errorf("invalid --confirm-timeout value")
			}
			timeout = v
		case arg == "--confirm-timeout":
			timeout = 10
		case arg == "--force":
			force = true
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Show what will be done
	fmt.Println(color.Bold("The following commands will be applied:"))
	fmt.Println()
	for _, cmd := range cfg.Commands {
		expanded := config.ExpandCommandString(cmd)
		fmt.Printf("  %s\n", color.Cyan(expanded))
	}
	fmt.Println()

	if !force {
		fmt.Print("Apply these changes? [y/N] ")
		if !confirm() {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Save state and start watcher if timeout requested
	if timeout > 0 {
		selfBin, _ := os.Executable()
		if err := revert.SaveAndStartWatcher(selfBin, timeout); err != nil {
			return fmt.Errorf("setup revert: %w", err)
		}
	}

	// Apply
	if err := applyConfig(cfg, false); err != nil {
		return err
	}

	if timeout > 0 {
		fmt.Printf("\nConfiguration applied. Run 'nic confirm' within %ds to keep changes.\n", timeout)
	} else {
		fmt.Println("Configuration reloaded.")
	}

	return nil
}

func cmdStatus() {
	state.PrintStatus(os.Stdout)

	// WiFi
	fmt.Printf("\n%s\n", color.Bold("WiFi:"))
	fmt.Printf("  %s\n", wifi.Status())

	// Revert status
	if revert.IsPending() {
		fmt.Printf("\n%s run 'nic confirm' to keep current configuration\n",
			color.BoldYellow("[!] Pending revert —"))
	}
}

func cmdShow(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	for _, cmd := range cfg.Commands {
		expanded := config.ExpandCommandString(cmd)
		fmt.Printf("  %s %s\n",
			color.Gray(fmt.Sprintf("[%s:%d]", cmd.File, cmd.LineNum)),
			expanded)
	}
	return nil
}

func cmdDryRun(configPath string) error {
	executor.DryRun = true
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	return applyConfig(cfg, false)
}

func cmdConfirm() error {
	if err := revert.Confirm(); err != nil {
		return err
	}
	fmt.Println(color.Green("Changes confirmed."))
	return nil
}

// isAlreadyExists reports whether an ip command error indicates the object
// already exists (EEXIST from the kernel). This covers all iproute2 objects
// generically without hardcoding which ones support "replace".
func isAlreadyExists(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "file exists") || strings.Contains(s, "already assigned")
}

// --- Helper functions ---

func setupLoopback() {
	_, _ = executor.RunIP("link", "set", "lo", "up")
	_, _ = executor.RunIP("addr", "add", "127.0.0.1/8", "dev", "lo")
	_, _ = executor.RunIP("addr", "add", "::1/128", "dev", "lo")
}

func waitForDAD() {
	// Wait for IPv6 Duplicate Address Detection to complete.
	// Tentative addresses cannot be used until DAD finishes.
	maxWait := 3 * time.Second
	interval := 200 * time.Millisecond
	deadline := time.Now().Add(maxWait)

	for time.Now().Before(deadline) {
		output := executor.RunSilent("ip", "-6", "addr", "show", "tentative")
		if output == "" {
			return // No tentative addresses, DAD complete
		}
		time.Sleep(interval)
	}

	if executor.Verbose {
		fmt.Println("Warning: IPv6 DAD did not complete within timeout")
	}
}

func confirm() bool {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}

// waitForShutdownSignal blocks until SIGINT or SIGTERM is received,
// then triggers graceful shutdown by stopping all DHCP clients.
func waitForShutdownSignal() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down gracefully...")
	dhcp.StopAll()

	// Remove PID file on shutdown
	_ = os.Remove("/run/nic/nic.pid")
}

// writePIDFile writes the current process PID to /run/nic/nic.pid
func writePIDFile() error {
	pidDir := "/run/nic"
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		return err
	}

	pid := os.Getpid()
	return os.WriteFile(filepath.Join(pidDir, "nic.pid"), []byte(fmt.Sprintf("%d\n", pid)), 0644)
}
