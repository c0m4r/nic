package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type CmdType int

const (
	CmdIPRoute2      CmdType = iota // ip ... (full or abbreviated iproute2 command)
	CmdAlias                        // alias <name> <iface>
	CmdPin                          // pin <name> <mac>
	CmdInclude                      // include <glob>
	CmdNameserver                   // nameserver <ip> / ns <ip>
	CmdWifi                         // wifi <ssid> <password> [iface]
	CmdDHCP                         // dhcp <iface> [client]
	CmdIfShortcut                   // if <iface> up/down  OR  up/down <iface>
	CmdIPShortcut                   // ip <addr>[/prefix] <iface>
	CmdRouteShortcut                // route <dest> [via <gw>] <iface>
)

type Command struct {
	Type    CmdType
	Raw     string
	Tokens  []string
	File    string
	LineNum int
}

type Config struct {
	Commands []Command
}

// Load parses the config file at path, following include directives.
func Load(path string) (*Config, error) {
	cfg := &Config{}
	if err := cfg.loadFile(path); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (cfg *Config) loadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	dir := filepath.Dir(path)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip inline comments
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		cmd, err := parseLine(line, path, lineNum)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNum, err)
		}

		// Handle include directives immediately
		if cmd.Type == CmdInclude {
			pattern := cmd.Tokens[1]
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(dir, pattern)
			}
			if err := cfg.handleInclude(pattern); err != nil {
				return fmt.Errorf("%s:%d: include: %w", path, lineNum, err)
			}
			continue
		}

		cfg.Commands = append(cfg.Commands, cmd)
	}

	return scanner.Err()
}

func (cfg *Config) handleInclude(pattern string) error {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("invalid glob %q: %w", pattern, err)
	}
	sort.Slice(matches, func(i, j int) bool {
		return naturalLess(filepath.Base(matches[i]), filepath.Base(matches[j]))
	})
	for _, match := range matches {
		if err := cfg.loadFile(match); err != nil {
			return err
		}
	}
	return nil
}

func parseLine(line, file string, lineNum int) (Command, error) {
	tokens := tokenize(line)
	if len(tokens) == 0 {
		return Command{}, fmt.Errorf("empty command")
	}

	cmd := Command{
		Raw:     line,
		Tokens:  tokens,
		File:    file,
		LineNum: lineNum,
	}

	switch tokens[0] {
	case "alias":
		if len(tokens) < 3 {
			return cmd, fmt.Errorf("alias requires name and interface: alias <name> <iface>")
		}
		cmd.Type = CmdAlias
		return cmd, nil

	case "pin":
		if len(tokens) < 3 {
			return cmd, fmt.Errorf("pin requires name and MAC: pin <name> <mac>")
		}
		cmd.Type = CmdPin
		return cmd, nil

	case "include":
		if len(tokens) < 2 {
			return cmd, fmt.Errorf("include requires a path or glob pattern")
		}
		cmd.Type = CmdInclude
		return cmd, nil

	case "nameserver":
		if len(tokens) < 2 {
			return cmd, fmt.Errorf("nameserver requires an IP address")
		}
		cmd.Type = CmdNameserver
		return cmd, nil

	case "ns":
		if len(tokens) < 2 {
			return cmd, fmt.Errorf("ns requires an IP address")
		}
		cmd.Type = CmdNameserver
		return cmd, nil

	case "wifi":
		if len(tokens) < 3 {
			return cmd, fmt.Errorf("wifi requires SSID and password: wifi <ssid> <password> [iface]")
		}
		cmd.Type = CmdWifi
		return cmd, nil

	case "dhcp":
		if len(tokens) < 2 {
			return cmd, fmt.Errorf("dhcp requires an interface: dhcp <iface> [client]")
		}
		cmd.Type = CmdDHCP
		return cmd, nil

	case "if":
		if len(tokens) < 3 {
			return cmd, fmt.Errorf("if requires interface and state: if <iface> up|down")
		}
		cmd.Type = CmdIfShortcut
		return cmd, nil

	case "up", "down":
		if len(tokens) < 2 {
			return cmd, fmt.Errorf("%s requires an interface: %s <iface>", tokens[0], tokens[0])
		}
		// Normalize: up eth0 → if eth0 up
		cmd.Tokens = []string{"if", tokens[1], tokens[0]}
		cmd.Type = CmdIfShortcut
		return cmd, nil

	case "route":
		if len(tokens) < 3 {
			return cmd, fmt.Errorf("route requires destination and interface: route <dest> [via <gw>] <iface>")
		}
		cmd.Type = CmdRouteShortcut
		return cmd, nil

	case "ip":
		// Distinguish between: ip <iproute2 command> and ip <addr> <iface> shortcut
		if len(tokens) >= 3 && isIPAddress(tokens[1]) {
			cmd.Type = CmdIPShortcut
			return cmd, nil
		}
		cmd.Type = CmdIPRoute2
		return cmd, nil

	default:
		return cmd, fmt.Errorf("unknown command: %s", tokens[0])
	}
}

// ExpandCommand returns the ip command args that should be executed for this command.
// Returns nil for commands that are not ip commands (alias, pin, ns, wifi, dhcp, include).
func ExpandCommand(cmd Command) []string {
	switch cmd.Type {
	case CmdIPRoute2:
		// Already an ip command, strip the leading "ip"
		return cmd.Tokens[1:]

	case CmdIfShortcut:
		// if <iface> up/down → ip link set <iface> up/down
		return []string{"link", "set", cmd.Tokens[1], cmd.Tokens[2]}

	case CmdIPShortcut:
		// ip <addr> <iface> → ip address add <addr> dev <iface>
		addr := ensureCIDR(cmd.Tokens[1])
		iface := cmd.Tokens[2]
		return []string{"address", "add", addr, "dev", iface}

	case CmdRouteShortcut:
		// route <dest> [via <gw>] <iface>
		return expandRouteShortcut(cmd.Tokens[1:])

	default:
		return nil
	}
}

// ExpandCommandString returns a human-readable form of the command.
func ExpandCommandString(cmd Command) string {
	switch cmd.Type {
	case CmdIPRoute2:
		return cmd.Raw
	case CmdIfShortcut:
		return fmt.Sprintf("ip link set %s %s", cmd.Tokens[1], cmd.Tokens[2])
	case CmdIPShortcut:
		addr := ensureCIDR(cmd.Tokens[1])
		return fmt.Sprintf("ip address add %s dev %s", addr, cmd.Tokens[2])
	case CmdRouteShortcut:
		args := expandRouteShortcut(cmd.Tokens[1:])
		return "ip " + strings.Join(args, " ")
	case CmdAlias:
		return fmt.Sprintf("alias %s → %s", cmd.Tokens[1], cmd.Tokens[2])
	case CmdPin:
		return fmt.Sprintf("pin %s → MAC %s", cmd.Tokens[1], cmd.Tokens[2])
	case CmdNameserver:
		return fmt.Sprintf("nameserver %s", cmd.Tokens[1])
	case CmdWifi:
		ssid := cmd.Tokens[1]
		iface := ""
		if len(cmd.Tokens) >= 4 {
			iface = " on " + cmd.Tokens[3]
		}
		return fmt.Sprintf("wifi connect %q%s", ssid, iface)
	case CmdDHCP:
		iface := cmd.Tokens[1]
		client := ""
		if len(cmd.Tokens) >= 3 {
			client = " using " + cmd.Tokens[2]
		}
		return fmt.Sprintf("dhcp %s%s", iface, client)
	default:
		return cmd.Raw
	}
}

func expandRouteShortcut(args []string) []string {
	// route <dest> [via <gw>] <iface>
	// → route add <dest> [via <gw>] dev <iface>
	result := []string{"route", "add"}

	hasVia := false
	hasDev := false
	for _, a := range args {
		if a == "via" {
			hasVia = true
		}
		if a == "dev" {
			hasDev = true
		}
	}

	if hasVia {
		// route <dest> via <gw> <iface>
		// Find the last token as interface (if no dev keyword)
		if !hasDev {
			last := args[len(args)-1]
			// Check if last token could be an interface (not an IP)
			if !isIPAddress(last) && last != "via" {
				result = append(result, args[:len(args)-1]...)
				result = append(result, "dev", last)
			} else {
				result = append(result, args...)
			}
		} else {
			result = append(result, args...)
		}
	} else {
		// route <dest> <iface>
		if len(args) >= 2 && !hasDev {
			result = append(result, args[0], "dev", args[1])
			result = append(result, args[2:]...)
		} else {
			result = append(result, args...)
		}
	}

	return result
}

// IsIPAddress reports whether s looks like an IP address (with optional CIDR prefix).
func IsIPAddress(s string) bool {
	return isIPAddress(s)
}

func isIPAddress(s string) bool {
	addr := s
	if idx := strings.Index(s, "/"); idx != -1 {
		addr = s[:idx]
	}
	return net.ParseIP(addr) != nil
}

// EnsureCIDR adds a default prefix length if missing (/32 for v4, /128 for v6).
func EnsureCIDR(s string) string {
	return ensureCIDR(s)
}

func ensureCIDR(s string) string {
	if strings.Contains(s, "/") {
		return s
	}
	if strings.Contains(s, ":") {
		return s + "/128"
	}
	return s + "/32"
}

// naturalLess compares two strings using natural sort order,
// where numeric segments are compared by value (e.g. "2" < "10").
func naturalLess(a, b string) bool {
	for {
		if a == b {
			return false
		}
		if a == "" {
			return true
		}
		if b == "" {
			return false
		}

		aDigit := a[0] >= '0' && a[0] <= '9'
		bDigit := b[0] >= '0' && b[0] <= '9'

		if aDigit && bDigit {
			// Extract numeric chunks
			ai := 0
			for ai < len(a) && a[ai] >= '0' && a[ai] <= '9' {
				ai++
			}
			bi := 0
			for bi < len(b) && b[bi] >= '0' && b[bi] <= '9' {
				bi++
			}
			an, _ := strconv.Atoi(a[:ai])
			bn, _ := strconv.Atoi(b[:bi])
			if an != bn {
				return an < bn
			}
			a = a[ai:]
			b = b[bi:]
		} else if aDigit != bDigit {
			return a[0] < b[0]
		} else {
			if a[0] != b[0] {
				return a[0] < b[0]
			}
			a = a[1:]
			b = b[1:]
		}
	}
}

func tokenize(line string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(line); i++ {
		ch := line[i]
		if inQuote {
			if ch == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(ch)
			}
			continue
		}
		switch ch {
		case '"', '\'':
			inQuote = true
			quoteChar = ch
		case ' ', '\t':
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}
