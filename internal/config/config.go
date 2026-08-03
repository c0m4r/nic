package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
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
	CmdDHCPv6                       // dhcpv6 <iface>
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
	loading  map[string]bool
}

// Load parses the config file at path, following include directives.
func Load(path string) (*Config, error) {
	cfg := &Config{loading: make(map[string]bool)}
	if err := cfg.loadFile(path); err != nil {
		return nil, err
	}
	return cfg, nil
}

// SaveSnapshot saves the fully expanded configuration (including included
// files) for later teardown or rollback.
func SaveSnapshot(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nic-config-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// LoadSnapshot loads a configuration previously written by SaveSnapshot.
func LoadSnapshot(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (cfg *Config) loadFile(path string) error {
	canonical, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return err
	}
	if resolved, resolveErr := filepath.EvalSymlinks(canonical); resolveErr == nil {
		canonical = resolved
	}
	if cfg.loading == nil {
		cfg.loading = make(map[string]bool)
	}
	if cfg.loading[canonical] {
		return fmt.Errorf("include cycle detected at %s", canonical)
	}
	cfg.loading[canonical] = true
	defer delete(cfg.loading, canonical)

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
	cleaned, err := stripInlineComment(line)
	if err != nil {
		return Command{}, err
	}
	tokens, err := tokenizeStrict(cleaned)
	if err != nil {
		return Command{}, err
	}
	if len(tokens) == 0 {
		return Command{}, fmt.Errorf("empty command")
	}

	cmd := Command{
		Raw:     cleaned,
		Tokens:  tokens,
		File:    file,
		LineNum: lineNum,
	}

	switch tokens[0] {
	case "alias":
		if len(tokens) != 3 {
			return cmd, fmt.Errorf("alias requires name and interface: alias <name> <iface>")
		}
		if err := validateInterfaceReference(tokens[1]); err != nil {
			return cmd, fmt.Errorf("invalid alias name: %w", err)
		}
		if err := validateInterfaceName(tokens[2]); err != nil {
			return cmd, fmt.Errorf("invalid alias interface: %w", err)
		}
		cmd.Type = CmdAlias
		return cmd, nil

	case "pin":
		if len(tokens) != 3 {
			return cmd, fmt.Errorf("pin requires name and MAC: pin <name> <mac>")
		}
		if err := validateInterfaceReference(tokens[1]); err != nil {
			return cmd, fmt.Errorf("invalid pin name: %w", err)
		}
		mac, err := net.ParseMAC(tokens[2])
		if err != nil || len(mac) != 6 {
			return cmd, fmt.Errorf("invalid MAC address %q", tokens[2])
		}
		cmd.Type = CmdPin
		return cmd, nil

	case "include":
		if len(tokens) != 2 {
			return cmd, fmt.Errorf("include requires a path or glob pattern")
		}
		cmd.Type = CmdInclude
		return cmd, nil

	case "nameserver":
		if len(tokens) != 2 {
			return cmd, fmt.Errorf("nameserver requires an IP address")
		}
		if net.ParseIP(tokens[1]) == nil {
			return cmd, fmt.Errorf("invalid nameserver address %q", tokens[1])
		}
		cmd.Type = CmdNameserver
		return cmd, nil

	case "ns":
		if len(tokens) != 2 {
			return cmd, fmt.Errorf("ns requires an IP address")
		}
		if net.ParseIP(tokens[1]) == nil {
			return cmd, fmt.Errorf("invalid nameserver address %q", tokens[1])
		}
		cmd.Type = CmdNameserver
		return cmd, nil

	case "wifi":
		if len(tokens) < 3 || len(tokens) > 4 {
			return cmd, fmt.Errorf("wifi requires SSID and password: wifi <ssid> <password> [iface]")
		}
		if len(tokens) == 4 {
			if err := validateInterfaceReference(tokens[3]); err != nil {
				return cmd, fmt.Errorf("invalid WiFi interface: %w", err)
			}
		}
		cmd.Type = CmdWifi
		return cmd, nil

	case "dhcp":
		if len(tokens) < 2 || len(tokens) > 3 {
			return cmd, fmt.Errorf("dhcp requires an interface: dhcp <iface> [client]")
		}
		if err := validateInterfaceReference(tokens[1]); err != nil {
			return cmd, fmt.Errorf("invalid DHCP interface: %w", err)
		}
		if len(tokens) == 3 && tokens[2] != "native" && tokens[2] != "dhclient" &&
			tokens[2] != "dhcpcd" && tokens[2] != "udhcpc" {
			return cmd, fmt.Errorf("unsupported DHCP client %q", tokens[2])
		}
		cmd.Type = CmdDHCP
		return cmd, nil

	case "dhcpv6":
		if len(tokens) != 2 {
			return cmd, fmt.Errorf("dhcpv6 requires an interface: dhcpv6 <iface>")
		}
		if err := validateInterfaceReference(tokens[1]); err != nil {
			return cmd, fmt.Errorf("invalid DHCPv6 interface: %w", err)
		}
		cmd.Type = CmdDHCPv6
		return cmd, nil

	case "if":
		if len(tokens) != 3 {
			return cmd, fmt.Errorf("if requires interface and state: if <iface> up|down")
		}
		if err := validateInterfaceReference(tokens[1]); err != nil {
			return cmd, fmt.Errorf("invalid interface: %w", err)
		}
		if tokens[2] != "up" && tokens[2] != "down" {
			return cmd, fmt.Errorf("invalid interface state %q (use up or down)", tokens[2])
		}
		cmd.Type = CmdIfShortcut
		return cmd, nil

	case "up", "down":
		if len(tokens) != 2 {
			return cmd, fmt.Errorf("%s requires an interface: %s <iface>", tokens[0], tokens[0])
		}
		if err := validateInterfaceReference(tokens[1]); err != nil {
			return cmd, fmt.Errorf("invalid interface: %w", err)
		}
		// Normalize: up eth0 → if eth0 up
		cmd.Tokens = []string{"if", tokens[1], tokens[0]}
		cmd.Type = CmdIfShortcut
		return cmd, nil

	case "route":
		if err := validateRouteShortcut(tokens); err != nil {
			return cmd, err
		}
		cmd.Type = CmdRouteShortcut
		return cmd, nil

	case "ip":
		if len(tokens) < 2 {
			return cmd, fmt.Errorf("ip requires an iproute2 command or address shortcut")
		}
		// Distinguish between: ip <iproute2 command> and ip <addr> <iface> shortcut
		if len(tokens) >= 2 && isIPAddress(tokens[1]) {
			if len(tokens) != 3 {
				return cmd, fmt.Errorf("ip shortcut requires interface: ip <addr> <iface>")
			}
			if err := validateInterfaceReference(tokens[2]); err != nil {
				return cmd, fmt.Errorf("invalid IP shortcut interface: %w", err)
			}
			cmd.Type = CmdIPShortcut
			return cmd, nil
		}
		if before, _, hasPrefix := strings.Cut(tokens[1], "/"); hasPrefix && net.ParseIP(before) != nil {
			return cmd, fmt.Errorf("invalid IP prefix %q", tokens[1])
		}
		cmd.Type = CmdIPRoute2
		return cmd, nil

	default:
		return cmd, fmt.Errorf("unknown command: %s", tokens[0])
	}
}

func validateRouteShortcut(tokens []string) error {
	usage := fmt.Errorf("route requires: route <dest> [via <gateway>] <interface>")
	if len(tokens) < 3 || len(tokens) > 6 {
		return usage
	}
	if tokens[1] != "default" && !isIPAddress(tokens[1]) {
		return fmt.Errorf("invalid route destination %q", tokens[1])
	}
	switch len(tokens) {
	case 3:
		return validateInterfaceReference(tokens[2])
	case 4:
		if tokens[2] != "dev" {
			return usage
		}
		return validateInterfaceReference(tokens[3])
	case 5:
		if tokens[2] != "via" || net.ParseIP(tokens[3]) == nil {
			return usage
		}
		return validateInterfaceReference(tokens[4])
	case 6:
		if tokens[2] != "via" || net.ParseIP(tokens[3]) == nil || tokens[4] != "dev" {
			return usage
		}
		return validateInterfaceReference(tokens[5])
	default:
		return usage
	}
}

func validateInterfaceReference(name string) error {
	if name == "" {
		return fmt.Errorf("interface reference is empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("interface reference is too long")
	}
	if strings.ContainsRune(name, '/') || strings.ContainsRune(name, 0) {
		return fmt.Errorf("interface reference %q contains a path separator or NUL", name)
	}
	return nil
}

func validateInterfaceName(name string) error {
	if err := validateInterfaceReference(name); err != nil {
		return err
	}
	if len(name) > 15 {
		return fmt.Errorf("Linux interface name %q exceeds 15 bytes", name)
	}
	return nil
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
	case CmdDHCPv6:
		return fmt.Sprintf("dhcpv6 %s", cmd.Tokens[1])
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
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
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
			aNumber := strings.TrimLeft(a[:ai], "0")
			bNumber := strings.TrimLeft(b[:bi], "0")
			if aNumber == "" {
				aNumber = "0"
			}
			if bNumber == "" {
				bNumber = "0"
			}
			if len(aNumber) != len(bNumber) {
				return len(aNumber) < len(bNumber)
			}
			if aNumber != bNumber {
				return aNumber < bNumber
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

func stripInlineComment(line string) (string, error) {
	inQuote := false
	quoteChar := byte(0)
	escaped := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if inQuote {
			if ch == quoteChar {
				inQuote = false
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			inQuote = true
			quoteChar = ch
			continue
		}
		if ch == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return strings.TrimSpace(line[:i]), nil
		}
	}
	if inQuote {
		return "", fmt.Errorf("unterminated %c quote", quoteChar)
	}
	if escaped {
		return "", fmt.Errorf("trailing escape")
	}
	return strings.TrimSpace(line), nil
}

func tokenize(line string) []string {
	tokens, _ := tokenizeStrict(line)
	return tokens
}

func tokenizeStrict(line string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)
	escaped := false
	tokenStarted := false

	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			current.WriteByte(ch)
			escaped = false
			tokenStarted = true
			continue
		}
		if ch == '\\' {
			escaped = true
			tokenStarted = true
			continue
		}
		if inQuote {
			if ch == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(ch)
				tokenStarted = true
			}
			continue
		}
		switch ch {
		case '"', '\'':
			inQuote = true
			quoteChar = ch
			tokenStarted = true
		case ' ', '\t':
			if tokenStarted {
				tokens = append(tokens, current.String())
				current.Reset()
				tokenStarted = false
			}
		default:
			current.WriteByte(ch)
			tokenStarted = true
		}
	}
	if escaped {
		return nil, fmt.Errorf("trailing escape")
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated %c quote", quoteChar)
	}
	if tokenStarted {
		tokens = append(tokens, current.String())
	}
	return tokens, nil
}
