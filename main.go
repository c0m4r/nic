package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
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
	"github.com/c0m4r/nic/internal/control"
	"github.com/c0m4r/nic/internal/dhcp"
	"github.com/c0m4r/nic/internal/dns"
	"github.com/c0m4r/nic/internal/executor"
	"github.com/c0m4r/nic/internal/revert"
	"github.com/c0m4r/nic/internal/state"
	"github.com/c0m4r/nic/internal/wifi"
)

var version = "0.1.4"

const defaultConfig = "/etc/nic.conf"

const shutdownCommandTimeout = 35 * time.Second

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
		if err := cmdStatus(); err != nil {
			fatal(err)
		}
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
	var sigChan chan os.Signal
	if daemonMode {
		// Hold the reload lock before publishing the PID record. This closes the
		// startup race where a new client could create a snapshot while stale
		// reload artifacts are being discarded.
		releaseStartupReload, claimErr := control.ClaimReload()
		if claimErr != nil {
			return claimErr
		}
		defer func() {
			if releaseStartupReload != nil {
				releaseStartupReload()
			}
		}()

		// Register handlers before publishing the PID record. DHCP and WiFi
		// setup can take time, and an immediate stop after startup must not use
		// SIGTERM's default action and leave a partial pending configuration.
		sigChan = make(chan os.Signal, 4)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)
		defer signal.Stop(sigChan)

		releasePID, err = control.ClaimDaemon()
		if err != nil {
			return err
		}
		defer releasePID()
		daemonRecord, recordErr := control.RecordForPID(os.Getpid())
		if recordErr != nil {
			return fmt.Errorf("identify daemon process: %w", recordErr)
		}
		if cleanupErr := discardStaleReloadArtifacts(daemonRecord); cleanupErr != nil {
			fmt.Fprintf(os.Stderr, "warning: discard stale reload request: %v\n", cleanupErr)
		}
		releaseStartupReload()
		releaseStartupReload = nil

		startupCtx, cancelStartup := context.WithCancel(context.Background())
		defer cancelStartup()
		restoreCommandContext := executor.UseCommandContext(startupCtx)
		stopped, reconcileErr := reconcileDaemonStartup(
			cfg, sigChan, cancelStartup, restoreCommandContext,
		)
		if reconcileErr != nil || stopped {
			return reconcileErr
		}
	} else if err := reconcileConfig(cfg, false); err != nil {
		return err
	}

	if daemonMode {
		if err := notifySystemd("READY=1\nSTATUS=nic network configuration applied"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: systemd readiness notification failed: %v\n", err)
		}
		fmt.Println("Running in daemon mode. Press Ctrl+C to stop.")
		return runDaemon(configPath, sigChan)
	}

	return nil
}

// reconcileDaemonStartup keeps termination responsive while reconciliation is
// running. Cancelling the startup context stops both external commands and the
// initial native DHCP exchange; restoring the executor context before waiting
// lets reconcileConfig perform its normal rollback with a bounded shutdown
// context.
func reconcileDaemonStartup(
	cfg *config.Config,
	sigChan <-chan os.Signal,
	cancel context.CancelFunc,
	restoreCommandContext func(),
) (bool, error) {
	result := make(chan error, 1)
	go func() {
		result <- reconcileConfig(cfg, true)
	}()

	for {
		select {
		case err := <-result:
			restoreCommandContext()
			return false, err
		case sig := <-sigChan:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				cancel()
				restoreCommandContext()
				shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownCommandTimeout)
				restoreShutdownContext := executor.UseCommandContext(shutdownCtx)
				// reconcileConfig rolls back a cancelled apply. Wait for that
				// rollback, then remove any previous configuration it restored.
				<-result
				fmt.Println("\nShutting down gracefully...")
				_ = notifySystemd("STOPPING=1\nSTATUS=nic is restoring the managed network state")
				cleanupErr := stopManagedConfig("")
				restoreShutdownContext()
				cancelShutdown()
				return true, cleanupErr
			case syscall.SIGHUP:
				rejectReloadDuringStartup()
			case syscall.SIGUSR1:
				response := control.Response{ID: "revert", Error: "daemon startup is still in progress"}
				if err := control.WriteJSONAtomic(control.RevertResponsePath, response, 0600); err != nil {
					fmt.Fprintf(os.Stderr, "revert response: %v\n", err)
				}
			}
		}
	}
}

func applyConfig(cfg *config.Config, daemonMode bool) error {
	if err := validateWifiConfigPermissions(cfg); err != nil {
		return err
	}
	if err := validateRollbackSafety(cfg); err != nil {
		return err
	}
	mgr := alias.NewManager()
	var nameservers []string
	var optionalV6Failures []optionalDHCPv6Failure

	// First pass: collect aliases, pins, and static resolver inputs. Resolver
	// policy must be in place before DHCP sessions start so later renewals cannot
	// replace configured nameservers.
	for _, cmd := range cfg.Commands {
		switch cmd.Type {
		case config.CmdAlias:
			mgr.AddAlias(cmd.Tokens[1], cmd.Tokens[2])
		case config.CmdPin:
			mgr.AddPin(cmd.Tokens[1], cmd.Tokens[2])
		case config.CmdNameserver:
			nameservers = append(nameservers, cmd.Tokens[1])
		}
	}

	// Resolve pins (look up actual interface names by MAC)
	if err := mgr.Resolve(); err != nil {
		return fmt.Errorf("resolve aliases: %w", err)
	}
	if err := dns.ConfigureStaticNameservers(nameservers); err != nil {
		return fmt.Errorf("configure resolv.conf: %w", err)
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
			// Applied before DHCP starts above.
			continue

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
				wrapped := fmt.Errorf("%s:%d: %w", cmd.File, cmd.LineNum, err)
				if config.DHCPv6Required(cmd) {
					return wrapped
				}
				// Severity depends on whether the interface ends up configured
				// by another address family, which is only known once the rest
				// of the configuration has been applied.
				optionalV6Failures = append(optionalV6Failures,
					optionalDHCPv6Failure{iface: iface, err: wrapped})
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
	if err := dns.ApplyManagedNameservers(); err != nil {
		return fmt.Errorf("write resolv.conf: %w", err)
	}

	// Wait for IPv6 DAD (duplicate address detection) to complete
	waitForDAD()

	// Resolved only after DAD so an address that is merely still tentative is
	// not mistaken for an unconfigured interface.
	return resolveOptionalDHCPv6(optionalV6Failures)
}

// optionalDHCPv6Failure records a DHCPv6 lease failure whose severity is not
// yet known, because it depends on how the rest of the interface configures.
type optionalDHCPv6Failure struct {
	iface string
	err   error
}

// resolveOptionalDHCPv6 downgrades DHCPv6 failures to warnings on interfaces
// that obtained an address some other way. This mirrors NetworkManager's
// may-fail model, where one address family may fail as long as the interface
// still ends up configured; an interface left with no address at all keeps the
// error. Mark the command `dhcpv6 <iface> required` to always fail instead.
func resolveOptionalDHCPv6(failures []optionalDHCPv6Failure) error {
	var fatal []error
	for _, failure := range failures {
		configured, err := state.HasGlobalAddress(failure.iface)
		if err != nil {
			fatal = append(fatal, errors.Join(failure.err, err))
			continue
		}
		if !configured {
			fatal = append(fatal, fmt.Errorf("%w (%s has no address from any other source)",
				failure.err, failure.iface))
			continue
		}
		fmt.Fprintf(os.Stderr, "warning: %v (continuing, %s is configured without DHCPv6)\n",
			failure.err, failure.iface)
	}
	return errors.Join(fatal...)
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
	dns.ResetManagedNameservers()
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

func stopManagedConfigBounded(fallbackConfigPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownCommandTimeout)
	defer cancel()
	restoreCommandContext := executor.UseCommandContext(ctx)
	defer restoreCommandContext()
	return stopManagedConfig(fallbackConfigPath)
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

	stopped, err := control.StopDaemon(45 * time.Second)
	if err != nil {
		return err
	}
	if stopped {
		// The daemon tears down its in-memory DHCP clients and managed config.
		if noManagedStateSnapshots() {
			return nil
		}
	}
	return stopManagedConfigBounded(configPath)
}

func noManagedStateSnapshots() bool {
	for _, path := range []string{
		control.AppliedConfigPath,
		control.PendingConfigPath,
		control.BaseStatePath,
	} {
		if _, err := os.Stat(path); err == nil || !os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// reverseIPCommand generates the reverse of an ip command for teardown.
func reverseIPCommand(args []string) []string {
	objectIndex, ok := ipCommandObjectIndex(args)
	if !ok {
		return nil
	}

	obj := canonicalIPObject(args[objectIndex])
	action := canonicalIPWord(args[objectIndex+1], map[string]string{
		"add": "add", "set": "set", "change": "set", "replace": "replace",
	})

	switch {
	case obj == "link" && action == "set":
		propertyIndex, ok := linkSetPropertyIndex(args, objectIndex)
		if !ok {
			return nil
		}
		result := make([]string, len(args))
		copy(result, args)
		for i := propertyIndex; i < len(result); i++ {
			a := result[i]
			if a == "up" {
				result[i] = "down"
				result[objectIndex], result[objectIndex+1] = "link", "set"
				return result
			}
			if a == "down" {
				result[objectIndex], result[objectIndex+1] = "link", "set"
				return result
			}
			if a == "master" && i+1 < len(result) {
				result = append(result[:i], result[i+2:]...)
				result = append(result, "nomaster")
				result[objectIndex], result[objectIndex+1] = "link", "set"
				return result
			}
		}
		return nil

	case obj == "link" && action == "add":
		name := linkAddName(args, objectIndex)
		if name != "" {
			return append(append([]string{}, args[:objectIndex]...), "link", "del", name)
		}

	case obj == "address" && (action == "add" || action == "replace"):
		result := make([]string, len(args))
		copy(result, args)
		result[objectIndex] = "address"
		result[objectIndex+1] = "del"
		return result

	case (obj == "route" || obj == "rule") && (action == "add" || action == "replace"):
		result := make([]string, len(args))
		copy(result, args)
		result[objectIndex] = obj
		result[objectIndex+1] = "del"
		return result
	}

	return nil
}

// validateRollbackSafety restricts iproute2 passthrough to operations that
// nic can reliably unwind. Applying a destructive command that is not in the
// snapshot or has no inverse would defeat the tool's rollback guarantee.
func validateRollbackSafety(cfg *config.Config) error {
	for _, cmd := range cfg.Commands {
		switch cmd.Type {
		case config.CmdIPRoute2, config.CmdIfShortcut, config.CmdIPShortcut, config.CmdRouteShortcut:
			args := config.ExpandCommand(cmd)
			if err := validateRollbackableIPCommand(args); err != nil {
				return fmt.Errorf("%s:%d: %w", cmd.File, cmd.LineNum, err)
			}
		}
	}
	return nil
}

func validateRollbackableIPCommand(args []string) error {
	objectIndex, ok := ipCommandObjectIndex(args)
	if !ok {
		return fmt.Errorf("cannot determine iproute2 object and action for rollback")
	}
	object := canonicalIPObject(args[objectIndex])
	action := canonicalIPWord(args[objectIndex+1], map[string]string{
		"add": "add", "set": "set", "change": "set", "replace": "replace",
		"delete": "delete", "del": "delete", "flush": "flush",
	})

	switch object {
	case "link":
		switch action {
		case "add":
			if linkAddName(args, objectIndex) == "" {
				return fmt.Errorf("link add requires an explicit interface name for rollback")
			}
			return nil
		case "set":
			return validateRollbackableLinkSet(args, objectIndex)
		case "delete", "flush":
			return fmt.Errorf("ip link %s is not supported because a removed link cannot be safely restored", action)
		default:
			return fmt.Errorf("ip link %s is not supported by rollback-safe configuration", args[objectIndex+1])
		}

	case "address", "route", "rule":
		if action == "add" || action == "replace" {
			return nil
		}
		return fmt.Errorf("ip %s %s is not supported by rollback-safe configuration", object, args[objectIndex+1])

	default:
		return fmt.Errorf("ip %s is not supported by rollback-safe configuration", args[objectIndex])
	}
}

func validateRollbackableLinkSet(args []string, objectIndex int) error {
	position, ok := linkSetPropertyIndex(args, objectIndex)
	if !ok {
		return fmt.Errorf("ip link set requires an interface and a property")
	}

	for position < len(args) {
		switch args[position] {
		case "up", "down", "nomaster":
			position++
		case "mtu", "address", "master":
			if position+1 >= len(args) {
				return fmt.Errorf("ip link set %s requires a value", args[position])
			}
			position += 2
		default:
			return fmt.Errorf("ip link set %s is not supported because it cannot be safely restored", args[position])
		}
	}
	return nil
}

func linkSetPropertyIndex(args []string, objectIndex int) (int, bool) {
	position := objectIndex + 2
	if position < len(args) && args[position] == "dev" {
		position++
	}
	if position >= len(args) {
		return 0, false
	}
	position++ // interface name
	return position, position < len(args)
}

func ipCommandObjectIndex(args []string) (int, bool) {
	index := 0
	for index < len(args) && (args[index] == "-4" || args[index] == "-6") {
		index++
	}
	return index, index+1 < len(args)
}

func linkAddName(args []string, objectIndex int) string {
	start := objectIndex + 2
	for i := start; i < len(args) && args[i] != "type"; i++ {
		switch args[i] {
		case "name", "dev":
			if i+1 < len(args) && args[i+1] != "type" {
				return args[i+1]
			}
			return ""
		case "link", "address", "broadcast", "index", "mtu", "numtxqueues",
			"numrxqueues", "txqueuelen", "group", "netns":
			// Creation options before "type" consume one value. In
			// particular, "link" names the parent rather than the link
			// being created.
			i++
		default:
			if i == start {
				return args[i]
			}
		}
	}
	return ""
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
		if err := requestDaemonReloadLoaded(configPath, cfg, options.timeout); err != nil {
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
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	return requestDaemonReloadLoaded(configPath, cfg, timeout)
}

// requestDaemonReloadLoaded sends the exact configuration the CLI reviewed to
// the daemon. The daemon reads the protected snapshot rather than reopening a
// relative path or a file that may have changed after confirmation.
func requestDaemonReloadLoaded(configPath string, cfg *config.Config, timeout int) error {
	release, err := control.ClaimReload()
	if err != nil {
		return err
	}
	defer release()
	daemonRecord, err := control.DaemonRecord()
	if err != nil {
		return err
	}

	id := control.NewRequestID()
	snapshotPath := filepath.Join(control.RunDir, "reload-"+id+".json")
	if err := config.SaveSnapshot(snapshotPath, cfg); err != nil {
		return fmt.Errorf("save reload snapshot: %w", err)
	}
	request := control.ReloadRequest{
		ID:           id,
		ConfigPath:   configPath,
		SnapshotPath: snapshotPath,
		Timeout:      timeout,
		Daemon:       daemonRecord,
	}
	_ = os.Remove(control.ReloadResponsePath)
	if err := control.WriteJSONAtomic(control.ReloadRequestPath, request, 0600); err != nil {
		_ = os.Remove(snapshotPath)
		return err
	}
	if err := control.SignalProcessRecord(daemonRecord, syscall.SIGHUP); err != nil {
		_ = os.Remove(control.ReloadRequestPath)
		_ = os.Remove(snapshotPath)
		return err
	}
	if err := control.WaitResponse(control.ReloadResponsePath, id, 2*time.Minute); err != nil {
		// If the daemon never claimed this request, make sure a later raw HUP
		// cannot apply it. The snapshot is deliberately left for startup's
		// orphan cleanup because the daemon may have read the request already.
		var pending control.ReloadRequest
		if control.ReadJSON(control.ReloadRequestPath, &pending) == nil && pending.ID == id {
			_ = os.Remove(control.ReloadRequestPath)
		}
		return err
	}
	return nil
}

func cmdStatus() error {
	if err := state.PrintStatus(os.Stdout); err != nil {
		return err
	}

	// WiFi
	fmt.Printf("\n%s\n", color.Bold("WiFi:"))
	fmt.Printf("  %s\n", wifi.Status())

	// Revert status
	if revert.IsPending() {
		fmt.Printf("\n%s run 'nic confirm' to keep current configuration\n",
			color.BoldYellow("[!] Pending revert —"))
	}
	return nil
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

// notifySystemd implements the small sd_notify protocol directly so nic can
// report readiness only after its network configuration has succeeded. It is a
// no-op outside a systemd service.
func notifySystemd(message string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	if !strings.HasPrefix(socket, "/") && !strings.HasPrefix(socket, "@") {
		return fmt.Errorf("invalid NOTIFY_SOCKET")
	}
	if strings.HasPrefix(socket, "@") {
		// Linux abstract Unix sockets are represented by a leading NUL byte.
		socket = "\x00" + strings.TrimPrefix(socket, "@")
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte(message))
	return err
}

func isManagedReloadSnapshot(path string) bool {
	clean := filepath.Clean(path)
	if path == "" || filepath.Dir(clean) != filepath.Clean(control.RunDir) {
		return false
	}
	base := filepath.Base(clean)
	if !strings.HasPrefix(base, "reload-") || !strings.HasSuffix(base, ".json") {
		return false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(base, "reload-"), ".json")
	parts := strings.Split(id, "-")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if _, err := strconv.ParseUint(part, 10, 64); err != nil {
			return false
		}
	}
	return true
}

func removeManagedReloadSnapshot(path string) error {
	if !isManagedReloadSnapshot(path) {
		return nil
	}
	if err := os.Remove(filepath.Clean(path)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func discardStaleReloadArtifacts(current control.PIDRecord) error {
	var cleanupErrors []error
	preservedSnapshot := ""
	var request control.ReloadRequest
	requestErr := control.ReadJSON(control.ReloadRequestPath, &request)
	if requestErr == nil && request.Daemon == current {
		if isManagedReloadSnapshot(request.SnapshotPath) {
			preservedSnapshot = filepath.Clean(request.SnapshotPath)
		}
	} else {
		if requestErr == nil {
			cleanupErrors = append(cleanupErrors, removeManagedReloadSnapshot(request.SnapshotPath))
		}
		if err := os.Remove(control.ReloadRequestPath); err != nil && !os.IsNotExist(err) {
			cleanupErrors = append(cleanupErrors, err)
		}
	}

	entries, err := os.ReadDir(control.RunDir)
	if err != nil && !os.IsNotExist(err) {
		cleanupErrors = append(cleanupErrors, err)
	}
	for _, entry := range entries {
		path := filepath.Join(control.RunDir, entry.Name())
		if entry.IsDir() || !isManagedReloadSnapshot(path) || filepath.Clean(path) == preservedSnapshot {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	if err := os.Remove(control.ReloadResponsePath); err != nil && !os.IsNotExist(err) {
		cleanupErrors = append(cleanupErrors, err)
	}
	return errors.Join(cleanupErrors...)
}

func rejectReloadDuringStartup() {
	var request control.ReloadRequest
	if err := control.ReadJSON(control.ReloadRequestPath, &request); err != nil {
		fmt.Fprintln(os.Stderr, "reload ignored: no daemon reload request")
		return
	}
	_ = os.Remove(control.ReloadRequestPath)
	_ = removeManagedReloadSnapshot(request.SnapshotPath)
	response := control.Response{ID: request.ID, Error: "daemon startup is still in progress"}
	if err := control.WriteJSONAtomic(control.ReloadResponsePath, response, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "reload response: %v\n", err)
	}
}

func runDaemon(configPath string, sigChan <-chan os.Signal) error {
	daemonRecord, err := control.RecordForPID(os.Getpid())
	if err != nil {
		return fmt.Errorf("identify daemon process: %w", err)
	}
	for sig := range sigChan {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			fmt.Println("\nShutting down gracefully...")
			_ = notifySystemd("STOPPING=1\nSTATUS=nic is restoring the managed network state")
			return stopManagedConfigBounded("")

		case syscall.SIGHUP:
			var request control.ReloadRequest
			hasRequest := control.ReadJSON(control.ReloadRequestPath, &request) == nil
			if !hasRequest {
				// Reloads must arrive through the control request so the daemon
				// never reopens an unreviewed on-disk configuration on a raw HUP.
				fmt.Fprintln(os.Stderr, "reload ignored: no daemon reload request")
				continue
			}
			_ = os.Remove(control.ReloadRequestPath)
			if request.ConfigPath == "" {
				request.ConfigPath = configPath
			}
			var reloadErr error
			switch {
			case request.Daemon != daemonRecord:
				_ = removeManagedReloadSnapshot(request.SnapshotPath)
				reloadErr = fmt.Errorf("reload request targets a different daemon instance")
			case !isManagedReloadSnapshot(request.SnapshotPath):
				reloadErr = fmt.Errorf("reload request has an invalid configuration snapshot path")
			default:
				cfg, loadErr := config.LoadSnapshot(request.SnapshotPath)
				// Once the daemon has opened the snapshot, it owns cleanup. Keep it
				// until this point so a client timing out cannot race the daemon.
				_ = removeManagedReloadSnapshot(request.SnapshotPath)
				if loadErr != nil {
					reloadErr = fmt.Errorf("load requested configuration snapshot: %w", loadErr)
				} else {
					reloadErr = changeConfigurationLoaded(request.ConfigPath, cfg, true, request.Timeout)
				}
			}
			response := control.Response{ID: request.ID}
			if reloadErr != nil {
				response.Error = reloadErr.Error()
			}
			if writeErr := control.WriteJSONAtomic(control.ReloadResponsePath, response, 0600); writeErr != nil {
				fmt.Fprintf(os.Stderr, "reload response: %v\n", writeErr)
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

	var previousDNS dns.ManagedState
	previousReapplied := false
	previous, configErr := config.LoadSnapshot(configPath)
	if configErr == nil {
		if err := applyConfig(previous, daemonMode); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("reapply previous configuration: %w", err))
		} else {
			previousDNS = dns.CaptureManagedState()
			previousReapplied = true
			if err := config.SaveSnapshot(control.AppliedConfigPath, previous); err != nil {
				restoreErrors = append(restoreErrors, fmt.Errorf("save previous configuration: %w", err))
			}
		}
	} else if os.IsNotExist(configErr) {
		_ = os.Remove(control.AppliedConfigPath)
	} else {
		restoreErrors = append(restoreErrors, fmt.Errorf("load previous configuration: %w", configErr))
	}

	if err := state.RestoreState(statePath); err != nil {
		restoreErrors = append(restoreErrors, fmt.Errorf("restore captured state: %w", err))
	}
	if previousReapplied {
		if err := dns.RestoreManagedState(previousDNS); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("restore managed DNS policy: %w", err))
		}
	}
	if len(restoreErrors) == 0 {
		_ = os.Remove(control.PendingConfigPath)
	}
	return errors.Join(restoreErrors...)
}
