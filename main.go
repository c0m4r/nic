package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/c0m4r/nic/internal/alias"
	"github.com/c0m4r/nic/internal/color"
	"github.com/c0m4r/nic/internal/config"
	"github.com/c0m4r/nic/internal/control"
	"github.com/c0m4r/nic/internal/dhcp"
	"github.com/c0m4r/nic/internal/dns"
	"github.com/c0m4r/nic/internal/executor"
	"github.com/c0m4r/nic/internal/revert"
	"github.com/c0m4r/nic/internal/state"
	"github.com/c0m4r/nic/internal/wifi"
)

var version = "0.1.3"

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
			} else {
				fatal(fmt.Errorf("unknown start option %q", arg))
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
	case "__restore-snapshot":
		if len(cmdArgs) != 2 {
			fatal(fmt.Errorf("restore-snapshot requires state and config paths"))
		}
		if err := restoreSavedSnapshot(cmdArgs[0], cmdArgs[1], false); err != nil {
			fatal(err)
		}
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
  --no-rollback          Apply restart/reload without a confirmation watcher
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

	var releasePID func()
	if daemonMode {
		releasePID, err = control.ClaimDaemon()
		if err != nil {
			return err
		}
		defer releasePID()
	}

	if err := reconcileConfig(cfg, daemonMode); err != nil {
		return err
	}

	if daemonMode {
		fmt.Println("Running in daemon mode. Press Ctrl+C to stop.")
		return runDaemon(configPath)
	}

	return nil
}

func applyConfig(cfg *config.Config, daemonMode bool) error {
	if err := validateWifiConfigPermissions(cfg); err != nil {
		return err
	}
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

func validateWifiConfigPermissions(cfg *config.Config) error {
	checked := make(map[string]bool)
	for _, cmd := range cfg.Commands {
		if cmd.Type != config.CmdWifi || checked[cmd.File] {
			continue
		}
		checked[cmd.File] = true
		info, err := os.Stat(cmd.File)
		if err != nil {
			return fmt.Errorf("check WiFi config permissions for %s: %w", cmd.File, err)
		}
		if info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("%s contains WiFi credentials and must not be accessible by group or others (run: chmod 600 %s)", cmd.File, cmd.File)
		}
	}
	return nil
}

func ensureBaseline() (bool, error) {
	if _, err := os.Stat(control.BaseStatePath); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if _, err := os.Stat(control.AppliedConfigPath); err == nil {
		return false, fmt.Errorf("applied configuration exists without a baseline snapshot; stop nic before starting it again")
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if _, err := os.Stat(control.PendingConfigPath); err == nil {
		return false, fmt.Errorf("interrupted configuration exists without a baseline snapshot; stop nic before starting it again")
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := os.MkdirAll(control.RunDir, 0755); err != nil {
		return false, err
	}
	if err := state.SaveState(control.BaseStatePath); err != nil {
		return false, err
	}
	return true, nil
}

// reconcileConfig returns the machine to the pre-nic baseline before applying
// the desired configuration. This makes reload remove obsolete state instead
// of accumulating addresses, routes, DNS, and virtual links.
func reconcileConfig(cfg *config.Config, daemonMode bool) error {
	baselineCreated, err := ensureBaseline()
	if err != nil {
		return fmt.Errorf("capture baseline: %w", err)
	}

	pending, pendingErr := config.LoadSnapshot(control.PendingConfigPath)
	hadPending := pendingErr == nil
	if pendingErr != nil && !os.IsNotExist(pendingErr) {
		return fmt.Errorf("load interrupted configuration: %w", pendingErr)
	}

	old, oldErr := config.LoadSnapshot(control.AppliedConfigPath)
	hadOld := oldErr == nil
	if oldErr != nil && !os.IsNotExist(oldErr) {
		return fmt.Errorf("load applied configuration: %w", oldErr)
	}
	if hadOld || hadPending {
		var teardownErr error
		if hadPending {
			teardownErr = errors.Join(teardownErr, teardownConfig(pending))
		}
		if hadOld {
			teardownErr = errors.Join(teardownErr, teardownConfig(old))
		}
		restoreErr := state.RestoreState(control.BaseStatePath)
		if err := errors.Join(teardownErr, restoreErr); err != nil {
			return fmt.Errorf("restore baseline: %w", err)
		}
		_ = os.Remove(control.PendingConfigPath)
	} else if !baselineCreated {
		if err := state.RestoreState(control.BaseStatePath); err != nil {
			return fmt.Errorf("restore baseline after interrupted apply: %w", err)
		}
	}

	// Record intent before making changes so a later invocation can tear down a
	// configuration interrupted by process death before it was fully applied.
	if err := config.SaveSnapshot(control.PendingConfigPath, cfg); err != nil {
		return fmt.Errorf("save pending configuration: %w", err)
	}
	if err := applyConfig(cfg, daemonMode); err != nil {
		rollbackErr := rollbackFailedApply(cfg, old, hadOld, daemonMode)
		if rollbackErr == nil {
			_ = os.Remove(control.PendingConfigPath)
		}
		return errors.Join(err, rollbackErr)
	}
	if err := config.SaveSnapshot(control.AppliedConfigPath, cfg); err != nil {
		rollbackErr := rollbackFailedApply(cfg, old, hadOld, daemonMode)
		if rollbackErr == nil {
			_ = os.Remove(control.PendingConfigPath)
		}
		return errors.Join(fmt.Errorf("save applied configuration: %w", err), rollbackErr)
	}
	if err := os.Remove(control.PendingConfigPath); err != nil && !os.IsNotExist(err) {
		rollbackErr := rollbackFailedApply(cfg, old, hadOld, daemonMode)
		return errors.Join(fmt.Errorf("clear pending configuration: %w", err), rollbackErr)
	}
	return nil
}

func rollbackFailedApply(attempted, previous *config.Config, hadPrevious, daemonMode bool) error {
	var rollbackErrors []error
	if err := teardownConfig(attempted); err != nil {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("tear down failed configuration: %w", err))
	}
	if err := state.RestoreState(control.BaseStatePath); err != nil {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("restore baseline after failure: %w", err))
	}
	if hadPrevious {
		if err := applyConfig(previous, daemonMode); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("reapply previous configuration: %w", err))
		} else if err := config.SaveSnapshot(control.AppliedConfigPath, previous); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	} else {
		_ = os.Remove(control.AppliedConfigPath)
	}
	return errors.Join(rollbackErrors...)
}

func teardownConfig(cfg *config.Config) error {
	var teardownErrors []error
	if err := dhcp.StopAll(); err != nil {
		teardownErrors = append(teardownErrors, err)
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
	if err := mgr.Resolve(); err != nil {
		teardownErrors = append(teardownErrors, err)
	}

	disconnected := make(map[string]bool)
	for _, cmd := range cfg.Commands {
		if cmd.Type != config.CmdWifi {
			continue
		}
		iface := ""
		if len(cmd.Tokens) >= 4 {
			iface = cmd.Tokens[3]
			if resolved, ok := mgr.Get(iface); ok {
				iface = resolved
			}
		} else {
			managed := wifi.ManagedInterfaces()
			if len(managed) > 0 {
				for _, managedIface := range managed {
					if !disconnected[managedIface] {
						if err := wifi.Disconnect(managedIface); err != nil {
							teardownErrors = append(teardownErrors, err)
						}
						disconnected[managedIface] = true
					}
				}
				continue
			}
			iface = wifi.DetectInterface()
		}
		if iface != "" && !disconnected[iface] {
			if err := wifi.Disconnect(iface); err != nil {
				teardownErrors = append(teardownErrors, err)
			}
			disconnected[iface] = true
		}
	}

	for i := len(cfg.Commands) - 1; i >= 0; i-- {
		cmd := cfg.Commands[i]
		switch cmd.Type {
		case config.CmdIPRoute2, config.CmdIfShortcut, config.CmdIPShortcut, config.CmdRouteShortcut:
			ipArgs := config.ExpandCommand(cmd)
			if ipArgs == nil {
				continue
			}
			ipArgs = mgr.ResolveInTokens(ipArgs)
			if reverseArgs := reverseIPCommand(ipArgs); reverseArgs != nil {
				if _, err := executor.RunIP(reverseArgs...); err != nil && !isBenignTeardownError(err) {
					teardownErrors = append(teardownErrors,
						fmt.Errorf("%s:%d: %w", cmd.File, cmd.LineNum, err))
				}
			}
		}
	}

	if err := dns.Unguard(); err != nil {
		teardownErrors = append(teardownErrors, err)
	}
	return errors.Join(teardownErrors...)
}

func stopManagedConfig(fallbackConfigPath string) error {
	pending, pendingErr := config.LoadSnapshot(control.PendingConfigPath)
	if pendingErr != nil && !os.IsNotExist(pendingErr) {
		return pendingErr
	}
	cfg, err := config.LoadSnapshot(control.AppliedConfigPath)
	if err != nil && os.IsNotExist(err) && fallbackConfigPath != "" {
		cfg, err = config.Load(fallbackConfigPath)
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	var teardownErr error
	if pending != nil {
		teardownErr = errors.Join(teardownErr, teardownConfig(pending))
	}
	if cfg != nil {
		teardownErr = errors.Join(teardownErr, teardownConfig(cfg))
	}
	var restoreErr error
	if _, err := os.Stat(control.BaseStatePath); err == nil {
		restoreErr = state.RestoreState(control.BaseStatePath)
	} else if !os.IsNotExist(err) {
		restoreErr = err
	}
	if err := errors.Join(teardownErr, restoreErr); err != nil {
		return err
	}
	_ = os.Remove(control.AppliedConfigPath)
	_ = os.Remove(control.PendingConfigPath)
	_ = os.Remove(control.BaseStatePath)
	return nil
}

func cmdStop(configPath string, cmdArgs []string) error {
	force := false
	for _, arg := range cmdArgs {
		if arg == "--force" {
			force = true
		} else {
			return fmt.Errorf("unknown stop option %q", arg)
		}
	}

	if !force {
		fmt.Print("This will tear down all network configuration. Continue? [y/N] ")
		if !confirm() {
			fmt.Println("Aborted.")
			return nil
		}
	}

	stopped, err := control.StopDaemon(15 * time.Second)
	if err != nil {
		return err
	}
	if stopped {
		// The daemon tears down its in-memory DHCP clients and managed config.
		if _, statErr := os.Stat(control.AppliedConfigPath); os.IsNotExist(statErr) {
			return nil
		}
	}
	return stopManagedConfig(configPath)
}

// reverseIPCommand generates the reverse of an ip command for teardown.
func reverseIPCommand(args []string) []string {
	if len(args) < 2 {
		return nil
	}

	obj := canonicalIPObject(args[0])
	action := canonicalIPWord(args[1], map[string]string{
		"add": "add", "set": "set", "replace": "replace",
	})

	switch {
	case obj == "link" && action == "set":
		result := make([]string, len(args))
		copy(result, args)
		for i, a := range result {
			if a == "up" {
				result[i] = "down"
				result[0], result[1] = "link", "set"
				return result
			}
			if a == "down" {
				result[0], result[1] = "link", "set"
				return result
			}
			if a == "master" && i+1 < len(result) {
				result = append(result[:i], result[i+2:]...)
				result = append(result, "nomaster")
				result[0], result[1] = "link", "set"
				return result
			}
		}
		return nil

	case obj == "link" && action == "add":
		name := ""
		for i := 2; i+1 < len(args); i++ {
			if args[i] == "name" {
				name = args[i+1]
				break
			}
		}
		if name == "" && len(args) >= 3 && args[2] != "link" {
			name = args[2]
		}
		if name != "" {
			return []string{"link", "del", name}
		}

	case obj == "address" && (action == "add" || action == "replace"):
		result := make([]string, len(args))
		copy(result, args)
		result[0] = "address"
		result[1] = "del"
		return result

	case (obj == "route" || obj == "rule") && (action == "add" || action == "replace"):
		result := make([]string, len(args))
		copy(result, args)
		result[0] = obj
		result[1] = "del"
		return result
	}

	return nil
}

func canonicalIPObject(word string) string {
	if word == "" {
		return word
	}
	// iproute2 reserves the one-letter "r" abbreviation for route; rule is
	// abbreviated as "ru" or longer.
	switch {
	case word == "r" || strings.HasPrefix("route", word):
		return "route"
	case strings.HasPrefix("rule", word):
		return "rule"
	case strings.HasPrefix("link", word):
		return "link"
	case strings.HasPrefix("address", word) || strings.HasPrefix("addr", word):
		return "address"
	default:
		return word
	}
}

func canonicalIPWord(word string, candidates map[string]string) string {
	var match string
	for candidate, canonical := range candidates {
		if strings.HasPrefix(candidate, word) {
			if match != "" && match != canonical {
				return word
			}
			match = canonical
		}
	}
	if match == "" {
		return word
	}
	return match
}

func isBenignTeardownError(err error) bool {
	message := strings.ToLower(err.Error())
	for _, fragment := range []string{
		"cannot find device", "no such device", "no such process",
		"cannot assign requested address", "not found",
	} {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

type changeOptions struct {
	timeout int
	force   bool
}

func parseChangeOptions(args []string) (changeOptions, error) {
	options := changeOptions{timeout: 10}
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--confirm-timeout="):
			value, err := strconv.Atoi(strings.TrimPrefix(arg, "--confirm-timeout="))
			if err != nil || value < 0 {
				return options, fmt.Errorf("invalid --confirm-timeout value")
			}
			options.timeout = value
		case arg == "--confirm-timeout":
			options.timeout = 10
		case arg == "--no-rollback":
			options.timeout = 0
		case arg == "--force":
			options.force = true
		default:
			return options, fmt.Errorf("unknown option %q", arg)
		}
	}
	return options, nil
}

func cmdRestart(configPath string, cmdArgs []string) error {
	options, err := parseChangeOptions(cmdArgs)
	if err != nil {
		return err
	}

	if !options.force {
		fmt.Print("This will restart all network configuration. Continue? [y/N] ")
		if !confirm() {
			fmt.Println("Aborted.")
			return nil
		}
	}

	if control.IsDaemonRunning() {
		if err := requestDaemonReload(configPath, options.timeout); err != nil {
			return err
		}
	} else if err := changeConfiguration(configPath, false, options.timeout); err != nil {
		return err
	}

	if options.timeout > 0 {
		fmt.Printf("\nNetwork reconfigured. Run 'nic confirm' within %ds to keep changes.\n", options.timeout)
	} else {
		fmt.Println("Network restarted.")
	}

	return nil
}

func cmdReload(configPath string, cmdArgs []string) error {
	options, err := parseChangeOptions(cmdArgs)
	if err != nil {
		return err
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	fmt.Println(color.Bold("Configuration diff:"))
	fmt.Println()
	printConfigDiff(cfg)
	fmt.Println()

	if !options.force {
		fmt.Print("Apply these changes? [y/N] ")
		if !confirm() {
			fmt.Println("Aborted.")
			return nil
		}
	}

	if control.IsDaemonRunning() {
		if err := requestDaemonReload(configPath, options.timeout); err != nil {
			return err
		}
	} else {
		if err := changeConfigurationLoaded(configPath, cfg, false, options.timeout); err != nil {
			return err
		}
	}

	if options.timeout > 0 {
		fmt.Printf("\nConfiguration applied. Run 'nic confirm' within %ds to keep changes.\n", options.timeout)
	} else {
		fmt.Println("Configuration reloaded.")
	}

	return nil
}

func printConfigDiff(desired *config.Config) {
	current, err := config.LoadSnapshot(control.AppliedConfigPath)
	if err != nil {
		for _, cmd := range desired.Commands {
			fmt.Printf("  %s %s\n", color.Green("+"), color.Cyan(config.ExpandCommandString(cmd)))
		}
		return
	}

	oldCounts := make(map[string]int)
	newCounts := make(map[string]int)
	for _, cmd := range current.Commands {
		oldCounts[configCommandKey(cmd)]++
	}
	for _, cmd := range desired.Commands {
		newCounts[configCommandKey(cmd)]++
	}
	changes := 0
	for _, cmd := range current.Commands {
		key := configCommandKey(cmd)
		if newCounts[key] > 0 {
			newCounts[key]--
			continue
		}
		fmt.Printf("  %s %s\n", color.Red("-"), config.ExpandCommandString(cmd))
		changes++
	}
	for _, cmd := range desired.Commands {
		key := configCommandKey(cmd)
		if oldCounts[key] > 0 {
			oldCounts[key]--
			continue
		}
		fmt.Printf("  %s %s\n", color.Green("+"), color.Cyan(config.ExpandCommandString(cmd)))
		changes++
	}
	if changes == 0 {
		fmt.Printf("  %s\n", color.Dim("(no changes)"))
	}
}

func configCommandKey(cmd config.Command) string {
	var key strings.Builder
	_, _ = fmt.Fprintf(&key, "%d", cmd.Type)
	for _, token := range cmd.Tokens {
		_, _ = fmt.Fprintf(&key, ":%d:%s", len(token), token)
	}
	return key.String()
}

func changeConfiguration(configPath string, daemonMode bool, timeout int) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	return changeConfigurationLoaded(configPath, cfg, daemonMode, timeout)
}

func changeConfigurationLoaded(_ string, cfg *config.Config, daemonMode bool, timeout int) error {
	watcherPrepared := false
	if timeout > 0 {
		selfBin, err := os.Executable()
		if err != nil {
			return err
		}
		if err := revert.SaveAndStartWatcher(selfBin, timeout); err != nil {
			return fmt.Errorf("setup revert: %w", err)
		}
		watcherPrepared = true
	}
	if err := reconcileConfig(cfg, daemonMode); err != nil {
		if watcherPrepared {
			return errors.Join(err, revert.Cancel())
		}
		return err
	}
	if watcherPrepared {
		if err := revert.Arm(); err != nil {
			restoreErr := restoreSavedSnapshot(revert.PendingStatePath(), revert.SavedConfigPath(), daemonMode)
			cancelErr := revert.Cancel()
			return errors.Join(fmt.Errorf("arm revert: %w", err), restoreErr, cancelErr)
		}
	}
	return nil
}

func requestDaemonReload(configPath string, timeout int) error {
	id := control.NewRequestID()
	request := control.ReloadRequest{ID: id, ConfigPath: configPath, Timeout: timeout}
	_ = os.Remove(control.ReloadResponsePath)
	if err := control.WriteJSONAtomic(control.ReloadRequestPath, request, 0600); err != nil {
		return err
	}
	if err := control.SignalDaemon(syscall.SIGHUP); err != nil {
		_ = os.Remove(control.ReloadRequestPath)
		return err
	}
	return control.WaitResponse(control.ReloadResponsePath, id, 2*time.Minute)
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

func runDaemon(configPath string) error {
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)
	defer signal.Stop(sigChan)

	for sig := range sigChan {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			fmt.Println("\nShutting down gracefully...")
			return stopManagedConfig("")

		case syscall.SIGHUP:
			request := control.ReloadRequest{ConfigPath: configPath}
			hasRequest := control.ReadJSON(control.ReloadRequestPath, &request) == nil
			if hasRequest {
				_ = os.Remove(control.ReloadRequestPath)
			}
			if request.ConfigPath == "" {
				request.ConfigPath = configPath
			}
			err := changeConfiguration(request.ConfigPath, true, request.Timeout)
			if hasRequest {
				response := control.Response{ID: request.ID}
				if err != nil {
					response.Error = err.Error()
				}
				if writeErr := control.WriteJSONAtomic(control.ReloadResponsePath, response, 0600); writeErr != nil {
					fmt.Fprintf(os.Stderr, "reload response: %v\n", writeErr)
				}
			} else if err != nil {
				fmt.Fprintf(os.Stderr, "reload failed: %v\n", err)
			}

		case syscall.SIGUSR1:
			err := restoreSavedSnapshot(revert.PendingStatePath(), revert.SavedConfigPath(), true)
			response := control.Response{ID: "revert"}
			if err != nil {
				response.Error = err.Error()
			}
			if writeErr := control.WriteJSONAtomic(control.RevertResponsePath, response, 0600); writeErr != nil {
				fmt.Fprintf(os.Stderr, "revert response: %v\n", writeErr)
			}
		}
	}
	return nil
}

func restoreSavedSnapshot(statePath, configPath string, daemonMode bool) error {
	var restoreErrors []error
	if pending, err := config.LoadSnapshot(control.PendingConfigPath); err == nil {
		if err := teardownConfig(pending); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("tear down interrupted configuration: %w", err))
		}
	} else if !os.IsNotExist(err) {
		restoreErrors = append(restoreErrors, fmt.Errorf("load interrupted configuration: %w", err))
	}
	if current, err := config.LoadSnapshot(control.AppliedConfigPath); err == nil {
		if err := teardownConfig(current); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("tear down current configuration: %w", err))
		}
	} else if !os.IsNotExist(err) {
		restoreErrors = append(restoreErrors, fmt.Errorf("load current configuration: %w", err))
	}

	if _, err := os.Stat(control.BaseStatePath); err == nil {
		if err := state.RestoreState(control.BaseStatePath); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("restore baseline: %w", err))
		}
	} else if !os.IsNotExist(err) {
		restoreErrors = append(restoreErrors, err)
	}

	previous, configErr := config.LoadSnapshot(configPath)
	if configErr == nil {
		if err := applyConfig(previous, daemonMode); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("reapply previous configuration: %w", err))
		} else if err := config.SaveSnapshot(control.AppliedConfigPath, previous); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("save previous configuration: %w", err))
		}
	} else if os.IsNotExist(configErr) {
		_ = os.Remove(control.AppliedConfigPath)
	} else {
		restoreErrors = append(restoreErrors, fmt.Errorf("load previous configuration: %w", configErr))
	}

	if err := state.RestoreState(statePath); err != nil {
		restoreErrors = append(restoreErrors, fmt.Errorf("restore captured state: %w", err))
	}
	if len(restoreErrors) == 0 {
		_ = os.Remove(control.PendingConfigPath)
	}
	return errors.Join(restoreErrors...)
}
