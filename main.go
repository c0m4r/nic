package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
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
		if err := cmdStart(configPath); err != nil {
			fatal(err)
		}
	case "stop":
		if err := cmdStop(configPath); err != nil {
			fatal(err)
		}
	case "restart":
		if err := cmdRestart(configPath, cmdArgs); err != nil {
			fatal(err)
		}
	case "reload":
		if err := cmdReload(configPath, cmdArgs); err != nil {
			fatal(err)
		}
	case "status":
		cmdStatus()
	case "show":
		if err := cmdShow(configPath); err != nil {
			fatal(err)
		}
	case "dry-run":
		if err := cmdDryRun(configPath); err != nil {
			fatal(err)
		}
	case "confirm":
		if err := cmdConfirm(); err != nil {
			fatal(err)
		}
	case "install":
		if err := cmdInstall(cmdArgs); err != nil {
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
  install <init-system>  Install init scripts (systemd|openrc|sysv|runit)
  version                Show version

Options:
  --config=PATH          Config file path (default: /etc/nic.conf)
  --verbose, -v          Show commands being executed
  --confirm-timeout=N    Revert after N seconds if not confirmed (default: 10)
  --force                Skip confirmation prompts
  --help, -h             Show this help
  --version, -V          Show version
`)
}

// --- Command implementations ---

func cmdStart(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	return applyConfig(cfg)
}

func applyConfig(cfg *config.Config) error {
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
			if err := dhcp.Start(iface, client); err != nil {
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
				// Some errors are benign (e.g., address already exists)
				errStr := err.Error()
				if strings.Contains(errStr, "File exists") ||
					strings.Contains(errStr, "RTNETLINK answers: File exists") {
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

func cmdStop(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Stop DHCP clients
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

	// Stop
	if err := cmdStop(configPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning during stop: %v\n", err)
	}

	// Start
	if err := cmdStart(configPath); err != nil {
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
	if err := applyConfig(cfg); err != nil {
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
	return applyConfig(cfg)
}

func cmdConfirm() error {
	if err := revert.Confirm(); err != nil {
		return err
	}
	fmt.Println(color.Green("Changes confirmed."))
	return nil
}

func cmdInstall(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: nic install <systemd|openrc|sysv|runit>")
	}

	initSystem := args[0]
	selfBin, err := os.Executable()
	if err != nil {
		selfBin = "/usr/local/sbin/nic"
	}

	switch initSystem {
	case "systemd":
		return installSystemd(selfBin)
	case "openrc":
		return installOpenRC(selfBin)
	case "sysv":
		return installSysV(selfBin)
	case "runit":
		return installRunit(selfBin)
	default:
		return fmt.Errorf("unsupported init system: %s (use: systemd, openrc, sysv, runit)", initSystem)
	}
}

// --- Init system installation ---

func installSystemd(nicBin string) error {
	// Disable and mask systemd-networkd and systemd-resolved
	services := []string{"systemd-networkd", "systemd-resolved",
		"systemd-networkd-wait-online", "systemd-networkd.socket"}
	for _, svc := range services {
		_, _ = executor.Run("systemctl", "stop", svc)
		_, _ = executor.Run("systemctl", "disable", svc)
		_, _ = executor.Run("systemctl", "mask", svc)
	}

	// Write nic.service
	unit := fmt.Sprintf(`[Unit]
Description=nic - network interface configurator
DefaultDependencies=no
Wants=network.target
Before=network.target network-online.target
After=local-fs.target systemd-udevd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%s start
ExecStop=%s stop
ExecReload=%s reload --force

[Install]
WantedBy=multi-user.target
`, nicBin, nicBin, nicBin)

	if err := os.WriteFile("/etc/systemd/system/nic.service", []byte(unit), 0644); err != nil {
		return fmt.Errorf("write nic.service: %w", err)
	}

	if _, err := executor.Run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := executor.Run("systemctl", "enable", "nic.service"); err != nil {
		return err
	}

	fmt.Println("Installed and enabled nic.service")
	fmt.Println("Masked: systemd-networkd, systemd-resolved")
	return nil
}

func installOpenRC(nicBin string) error {
	script := fmt.Sprintf(`#!/sbin/openrc-run

description="nic - network interface configurator"
command="%s"

depend() {
    need localmount
    before net dns
    after udev
    provide net
}

start() {
    ebegin "Starting nic"
    ${command} start
    eend $?
}

stop() {
    ebegin "Stopping nic"
    ${command} stop
    eend $?
}

reload() {
    ebegin "Reloading nic"
    ${command} reload --force
    eend $?
}
`, nicBin)

	if err := os.WriteFile("/etc/init.d/nic", []byte(script), 0755); err != nil {
		return fmt.Errorf("write /etc/init.d/nic: %w", err)
	}

	_, _ = executor.Run("rc-update", "add", "nic", "boot")
	fmt.Println("Installed and enabled nic for OpenRC (boot runlevel)")
	return nil
}

func installSysV(nicBin string) error {
	script := fmt.Sprintf(`#!/bin/sh
### BEGIN INIT INFO
# Provides:          nic networking
# Required-Start:    mountkernfs $local_fs
# Required-Stop:     $local_fs
# Default-Start:     S
# Default-Stop:      0 6
# Short-Description: nic network interface configurator
### END INIT INFO

NIC="%s"

case "$1" in
    start)
        echo "Starting nic..."
        $NIC start
        ;;
    stop)
        echo "Stopping nic..."
        $NIC stop
        ;;
    restart)
        echo "Restarting nic..."
        $NIC stop
        $NIC start
        ;;
    reload)
        echo "Reloading nic..."
        $NIC reload --force
        ;;
    status)
        $NIC status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|reload|status}"
        exit 1
        ;;
esac
exit 0
`, nicBin)

	if err := os.WriteFile("/etc/init.d/nic", []byte(script), 0755); err != nil {
		return fmt.Errorf("write /etc/init.d/nic: %w", err)
	}

	if executor.CommandExists("update-rc.d") {
		_, _ = executor.Run("update-rc.d", "nic", "defaults")
	} else if executor.CommandExists("chkconfig") {
		_, _ = executor.Run("chkconfig", "--add", "nic")
	}

	fmt.Println("Installed /etc/init.d/nic (SysV)")
	return nil
}

func installRunit(nicBin string) error {
	_ = os.MkdirAll("/etc/sv/nic", 0755)

	run := fmt.Sprintf(`#!/bin/sh
exec %s start
`, nicBin)

	finish := fmt.Sprintf(`#!/bin/sh
%s stop
`, nicBin)

	if err := os.WriteFile("/etc/sv/nic/run", []byte(run), 0755); err != nil {
		return fmt.Errorf("write run: %w", err)
	}
	if err := os.WriteFile("/etc/sv/nic/finish", []byte(finish), 0755); err != nil {
		return fmt.Errorf("write finish: %w", err)
	}

	// Link to active services
	_ = os.Symlink("/etc/sv/nic", "/var/service/nic")

	fmt.Println("Installed /etc/sv/nic (runit)")
	return nil
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
