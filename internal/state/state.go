package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/c0m4r/nic/internal/color"
	"github.com/c0m4r/nic/internal/dns"
	"github.com/c0m4r/nic/internal/executor"
)

type Interface struct {
	IfIndex   int      `json:"ifindex"`
	IfName    string   `json:"ifname"`
	Flags     []string `json:"flags"`
	MTU       int      `json:"mtu"`
	Address   string   `json:"address"`
	OperState string   `json:"operstate"`
	Link      string   `json:"link_type"`
	Master    string   `json:"master,omitempty"`
}

type AddrEntry struct {
	IfName   string     `json:"ifname"`
	AddrInfo []AddrInfo `json:"addr_info"`
}

type AddrInfo struct {
	Family            string          `json:"family"`
	Local             string          `json:"local"`
	PrefixLen         int             `json:"prefixlen"`
	Scope             string          `json:"scope"`
	Label             string          `json:"label"`
	Dynamic           bool            `json:"dynamic"`
	Tentative         bool            `json:"tentative"`
	ValidLifeTime     json.RawMessage `json:"valid_life_time,omitempty"`
	PreferredLifeTime json.RawMessage `json:"preferred_life_time,omitempty"`
}

type Route struct {
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway"`
	Dev      string `json:"dev"`
	Protocol string `json:"protocol"`
	Scope    string `json:"scope"`
	Metric   int    `json:"metric"`
	Table    any    `json:"table,omitempty"`
	Type     string `json:"type,omitempty"`
	PrefSrc  string `json:"prefsrc,omitempty"`
	Src      string `json:"src,omitempty"`
}

// NetworkState holds a snapshot of the network configuration.
type NetworkState struct {
	CapturedAt  time.Time    `json:"captured_at,omitempty"`
	Interfaces  []Interface  `json:"interfaces"`
	Addresses   []AddrEntry  `json:"addresses"`
	Routes      []Route      `json:"routes"`
	Routes6     []Route      `json:"routes6"`
	RouteLines  []string     `json:"route_lines,omitempty"`
	Route6Lines []string     `json:"route6_lines,omitempty"`
	RuleLines   []string     `json:"rule_lines,omitempty"`
	Rule6Lines  []string     `json:"rule6_lines,omitempty"`
	DNS         dns.Snapshot `json:"dns"`
}

// GetInterfaces returns all network interfaces.
func GetInterfaces() ([]Interface, error) {
	output, runErr := executor.RunQuiet("ip", "-j", "link", "show")
	if runErr != nil {
		return nil, runErr
	}
	if output == "" {
		return nil, fmt.Errorf("failed to get interfaces")
	}
	var ifaces []Interface
	if err := json.Unmarshal([]byte(output), &ifaces); err != nil {
		return nil, fmt.Errorf("parse interfaces: %w", err)
	}
	return ifaces, nil
}

// GetAddresses returns all addresses on all interfaces.
func GetAddresses() ([]AddrEntry, error) {
	output, runErr := executor.RunQuiet("ip", "-j", "addr", "show")
	if runErr != nil {
		return nil, runErr
	}
	if output == "" {
		return nil, fmt.Errorf("failed to get addresses")
	}
	var addrs []AddrEntry
	if err := json.Unmarshal([]byte(output), &addrs); err != nil {
		return nil, fmt.Errorf("parse addresses: %w", err)
	}
	return addrs, nil
}

// GetRoutes returns IPv4 routes.
func GetRoutes() ([]Route, error) {
	output, runErr := executor.RunQuiet("ip", "-j", "route", "show", "table", "all")
	if runErr != nil {
		return nil, runErr
	}
	if output == "" {
		return nil, fmt.Errorf("failed to get routes")
	}
	var routes []Route
	if err := json.Unmarshal([]byte(output), &routes); err != nil {
		return nil, fmt.Errorf("parse routes: %w", err)
	}
	return routes, nil
}

// GetRoutes6 returns IPv6 routes.
func GetRoutes6() ([]Route, error) {
	output, runErr := executor.RunQuiet("ip", "-j", "-6", "route", "show", "table", "all")
	if runErr != nil {
		return nil, runErr
	}
	if output == "" {
		return nil, fmt.Errorf("failed to get ipv6 routes")
	}
	var routes []Route
	if err := json.Unmarshal([]byte(output), &routes); err != nil {
		return nil, fmt.Errorf("parse ipv6 routes: %w", err)
	}
	return routes, nil
}

// HasTentativeGlobalAddress reports whether an interface holds a global address
// that duplicate address detection has not finished with yet.
//
// This is the mirror image of HasGlobalAddress, and it exists because the two
// answer halves of one question. "No global address" can mean the interface
// failed to configure, or it can mean the address is already there and DAD is
// still running on it; only the second is worth waiting for. Link-local and host
// addresses are excluded here for the same reason they are excluded there:
// HasGlobalAddress would not count one, so waiting for one cannot change its
// answer.
func HasTentativeGlobalAddress(iface string) (bool, error) {
	output, err := executor.RunQuiet("ip", "-j", "addr", "show", "dev", iface)
	if err != nil {
		return false, err
	}
	if output == "" {
		return false, nil
	}
	var entries []AddrEntry
	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		return false, fmt.Errorf("parse addresses on %s: %w", iface, err)
	}
	for _, entry := range entries {
		for _, addr := range entry.AddrInfo {
			if !addr.Tentative {
				continue
			}
			if addr.Scope == "global" || addr.Scope == "universe" {
				return true, nil
			}
		}
	}
	return false, nil
}

// HasGlobalAddress reports whether an interface currently holds at least one
// usable address of any family. Link-local, host, and still-tentative addresses
// do not count, so this answers "did any address family configure this link".
func HasGlobalAddress(iface string) (bool, error) {
	output, err := executor.RunQuiet("ip", "-j", "addr", "show", "dev", iface)
	if err != nil {
		return false, err
	}
	if output == "" {
		return false, nil
	}
	var entries []AddrEntry
	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		return false, fmt.Errorf("parse addresses on %s: %w", iface, err)
	}
	for _, entry := range entries {
		for _, addr := range entry.AddrInfo {
			if addr.Tentative {
				continue
			}
			if addr.Scope == "global" || addr.Scope == "universe" {
				return true, nil
			}
		}
	}
	return false, nil
}

// Capture takes a full snapshot of current network state.
func Capture() (*NetworkState, error) {
	capturedAt := time.Now()
	ifaces, ifacesErr := GetInterfaces()
	addrs, addrsErr := GetAddresses()
	routes, routesErr := GetRoutes()
	routes6, routes6Err := GetRoutes6()
	routeLines, routeLinesErr := captureLines("ip", "-o", "route", "show", "table", "all")
	route6Lines, route6LinesErr := captureLines("ip", "-o", "-6", "route", "show", "table", "all")
	ruleLines, ruleLinesErr := captureLines("ip", "-o", "rule", "show")
	rule6Lines, rule6LinesErr := captureLines("ip", "-o", "-6", "rule", "show")
	dnsSnapshot, dnsErr := dns.Capture()
	if err := errors.Join(ifacesErr, addrsErr, routesErr, routes6Err,
		routeLinesErr, route6LinesErr, ruleLinesErr, rule6LinesErr, dnsErr); err != nil {
		return nil, err
	}

	return &NetworkState{
		CapturedAt:  capturedAt,
		Interfaces:  ifaces,
		Addresses:   addrs,
		Routes:      routes,
		Routes6:     routes6,
		RouteLines:  routeLines,
		Route6Lines: route6Lines,
		RuleLines:   ruleLines,
		Rule6Lines:  rule6Lines,
		DNS:         dnsSnapshot,
	}, nil
}

func captureLines(name string, args ...string) ([]string, error) {
	output, err := executor.RunQuiet(name, args...)
	if err != nil {
		return nil, err
	}
	if output == "" {
		return []string{}, nil
	}
	return strings.Split(output, "\n"), nil
}

// SaveState saves network state to a JSON file.
func SaveState(path string) error {
	st, err := Capture()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nic-state-*")
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

// LoadState loads network state from a JSON file.
func LoadState(path string) (*NetworkState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st NetworkState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// RestoreState restores network state from a saved snapshot.
func RestoreState(path string) error {
	st, err := LoadState(path)
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}

	var restoreErrors []error
	addError := func(operation string, err error) {
		if err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("%s: %w", operation, err))
		}
	}
	_, err = executor.RunIP("route", "flush", "table", "all")
	addError("flush all IPv4 routes", err)
	_, err = executor.RunIP("-6", "route", "flush", "table", "all")
	addError("flush all IPv6 routes", err)

	// Read live link properties so they are only rewritten where they actually
	// drifted. Tunnel devices such as sit0 reject every link-layer address
	// change with EOPNOTSUPP, which would otherwise fail each restore on any
	// machine that has one even though nic never touched the link. An interface
	// missing here keeps the zero value, so the restore is still attempted; a
	// failed read is not itself a restore failure, since each command below
	// still reports its own error.
	live, _ := GetInterfaces()
	liveByName := make(map[string]Interface, len(live))
	for _, iface := range live {
		liveByName[iface.IfName] = iface
	}

	// Bring links down before restoring mutable link properties, then flush all
	// addresses on non-loopback interfaces.
	for _, iface := range st.Interfaces {
		if iface.IfName == "lo" {
			continue
		}
		current := liveByName[iface.IfName]
		_, _ = executor.RunIP("link", "set", "dev", iface.IfName, "nomaster")
		_, err := executor.RunIP("link", "set", "dev", iface.IfName, "down")
		addError("bring down "+iface.IfName, err)
		_, err = executor.RunIP("addr", "flush", "dev", iface.IfName)
		addError("flush addresses on "+iface.IfName, err)
		if iface.Address != "" && iface.Address != "00:00:00:00:00:00" &&
			!strings.EqualFold(current.Address, iface.Address) {
			_, err = executor.RunIP("link", "set", "dev", iface.IfName, "address", iface.Address)
			addError("restore address on "+iface.IfName, err)
		}
		if iface.MTU > 0 && current.MTU != iface.MTU {
			_, err = executor.RunIP("link", "set", "dev", iface.IfName, "mtu", fmt.Sprintf("%d", iface.MTU))
			addError("restore MTU on "+iface.IfName, err)
		}
	}

	// Address lifetimes reported by ip are relative to the capture time. Reduce
	// them by the snapshot's age so rollback cannot resurrect an expired
	// DHCP/SLAAC address with its old full lifetime.
	elapsedLifetime := elapsedLifetimeSeconds(st.CapturedAt, time.Now())

	// Restore addresses.
	for _, entry := range st.Addresses {
		if entry.IfName == "lo" {
			continue
		}
		for _, addr := range entry.AddrInfo {
			if addr.Scope == "link" && addr.Family == "inet6" {
				continue // link-local, auto-generated by kernel
			}
			cidr := fmt.Sprintf("%s/%d", addr.Local, addr.PrefixLen)
			args := []string{"addr", "replace", cidr, "dev", entry.IfName}
			if addr.Scope != "" && addr.Scope != "global" && addr.Scope != "universe" {
				args = append(args, "scope", addr.Scope)
			}
			if addr.Label != "" && addr.Label != entry.IfName {
				args = append(args, "label", addr.Label)
			}
			lifetimeArgs, restore, err := restoreLifetimeArgs(addr, elapsedLifetime)
			if err != nil {
				addError("restore address "+cidr, err)
				continue
			}
			if !restore {
				continue
			}
			args = append(args, lifetimeArgs...)
			_, err = executor.RunIP(args...)
			addError("restore address "+cidr, err)
		}
	}

	// Restore IPv4 routes. Add link-scoped (host) routes first so that
	// gateway routes that depend on them resolve correctly.
	if st.RouteLines != nil {
		addError("restore IPv4 routes", restoreRouteLines(false, st.RouteLines))
	} else {
		addError("restore IPv4 routes", restoreRoutes(false, st.Routes))
	}

	// Restore IPv6 routes (were not restored at all before this fix).
	if st.Route6Lines != nil {
		addError("restore IPv6 routes", restoreRouteLines(true, st.Route6Lines))
	} else {
		addError("restore IPv6 routes", restoreRoutes(true, st.Routes6))
	}
	addError("restore IPv4 rules", restoreRules(false, st.RuleLines))
	addError("restore IPv6 rules", restoreRules(true, st.Rule6Lines))

	// Restore master relationships after all expected links exist.
	for _, iface := range st.Interfaces {
		if iface.IfName == "lo" {
			continue
		}
		args := []string{"link", "set", "dev", iface.IfName, "nomaster"}
		if iface.Master != "" {
			args = []string{"link", "set", "dev", iface.IfName, "master", iface.Master}
		}
		_, err := executor.RunIP(args...)
		if err != nil && iface.Master != "" {
			addError("restore master for "+iface.IfName, err)
		}
	}

	// Restore interface link states.
	for _, iface := range st.Interfaces {
		if iface.IfName == "lo" {
			continue
		}
		ifState := "down"
		for _, flag := range iface.Flags {
			if flag == "UP" {
				ifState = "up"
				break
			}
		}
		_, err := executor.RunIP("link", "set", "dev", iface.IfName, ifState)
		addError("restore link state for "+iface.IfName, err)
	}

	addError("restore DNS", dns.Restore(st.DNS))
	return errors.Join(restoreErrors...)
}

func restoreLifetimeArgs(addr AddrInfo, elapsed uint64) ([]string, bool, error) {
	valid, err := lifetimeArgument(addr.ValidLifeTime)
	if err != nil {
		return nil, false, fmt.Errorf("invalid valid_life_time: %w", err)
	}
	preferred, err := lifetimeArgument(addr.PreferredLifeTime)
	if err != nil {
		return nil, false, fmt.Errorf("invalid preferred_life_time: %w", err)
	}

	valid, expired, err := reduceLifetime(valid, elapsed)
	if err != nil {
		return nil, false, fmt.Errorf("invalid valid_life_time: %w", err)
	}
	if expired {
		return nil, false, nil
	}
	preferred, _, err = reduceLifetime(preferred, elapsed)
	if err != nil {
		return nil, false, fmt.Errorf("invalid preferred_life_time: %w", err)
	}

	args := make([]string, 0, 4)
	if valid != "" {
		args = append(args, "valid_lft", valid)
	}
	if preferred != "" {
		args = append(args, "preferred_lft", preferred)
	}
	return args, true, nil
}

func reduceLifetime(value string, elapsed uint64) (string, bool, error) {
	if value == "" || value == "forever" {
		return value, false, nil
	}
	seconds, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return "", false, err
	}
	if seconds <= elapsed {
		return "0", true, nil
	}
	return strconv.FormatUint(seconds-elapsed, 10), false, nil
}

func elapsedLifetimeSeconds(capturedAt, now time.Time) uint64 {
	if capturedAt.IsZero() || !now.After(capturedAt) {
		return 0
	}
	elapsed := now.Sub(capturedAt)
	seconds := elapsed / time.Second
	if elapsed%time.Second != 0 {
		seconds++
	}
	return uint64(seconds)
}

func lifetimeArgument(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", nil
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return "", fmt.Errorf("multiple values")
		}
		return "", err
	}

	switch value := value.(type) {
	case json.Number:
		if _, err := strconv.ParseUint(string(value), 10, 32); err != nil {
			return "", err
		}
		return string(value), nil
	case string:
		if value == "forever" {
			return value, nil
		}
		if _, err := strconv.ParseUint(value, 10, 32); err != nil {
			return "", fmt.Errorf("want an unsigned number or forever")
		}
		return value, nil
	default:
		return "", fmt.Errorf("want an unsigned number or forever")
	}
}

func restoreRouteLines(v6 bool, lines []string) error {
	var routeErrors []error
	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 || containsPair(fields, "proto", "kernel") {
			continue
		}
		args := make([]string, 0, len(fields)+3)
		if v6 {
			args = append(args, "-6")
		}
		args = append(args, "route", "replace")
		args = append(args, fields...)
		if _, err := executor.RunIP(args...); err != nil {
			routeErrors = append(routeErrors, fmt.Errorf("route %q: %w", line, err))
		}
	}
	return errors.Join(routeErrors...)
}

func restoreRules(v6 bool, desired []string) error {
	if desired == nil {
		return nil
	}
	current, err := captureLines("ip", append(familyArgs(v6), "-o", "rule", "show")...)
	if err != nil {
		return err
	}
	var ruleErrors []error
	for _, line := range current {
		priority, _, ok := splitRuleLine(line)
		if !ok || isDefaultRulePriority(priority) {
			continue
		}
		args := append(familyArgs(v6), "rule", "del", "priority", priority)
		if _, err := executor.RunIP(args...); err != nil {
			ruleErrors = append(ruleErrors, err)
		}
	}
	for _, line := range desired {
		priority, body, ok := splitRuleLine(line)
		if !ok || isDefaultRulePriority(priority) {
			continue
		}
		args := append(familyArgs(v6), "rule", "add", "priority", priority)
		args = append(args, strings.Fields(body)...)
		if _, err := executor.RunIP(args...); err != nil {
			ruleErrors = append(ruleErrors, fmt.Errorf("rule %q: %w", line, err))
		}
	}
	return errors.Join(ruleErrors...)
}

func familyArgs(v6 bool) []string {
	if v6 {
		return []string{"-6"}
	}
	return nil
}

func splitRuleLine(line string) (string, string, bool) {
	before, after, ok := strings.Cut(strings.TrimSpace(line), ":")
	priority := strings.TrimSpace(before)
	if !ok || priority == "" {
		return "", "", false
	}
	for _, r := range priority {
		if r < '0' || r > '9' {
			return "", "", false
		}
	}
	return priority, strings.TrimSpace(after), true
}

func isDefaultRulePriority(priority string) bool {
	return priority == "0" || priority == "32766" || priority == "32767"
}

func containsPair(fields []string, first, second string) bool {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == first && fields[i+1] == second {
			return true
		}
	}
	return false
}

// restoreRoutes replays a slice of routes, skipping kernel-generated ones and
// adding link-scoped routes before gateway routes so dependencies are met.
func restoreRoutes(v6 bool, routes []Route) error {
	var routeErrors []error
	// Two passes: link-scoped first, then the rest.
	for _, pass := range []string{"link", ""} {
		for _, r := range routes {
			if r.Protocol == "kernel" {
				continue // auto-created by kernel when addresses are added
			}
			if pass == "link" && r.Scope != "link" {
				continue
			}
			if pass == "" && r.Scope == "link" {
				continue
			}
			if err := applyRoute(v6, r); err != nil {
				routeErrors = append(routeErrors, err)
			}
		}
	}
	return errors.Join(routeErrors...)
}

func applyRoute(v6 bool, r Route) error {
	var args []string
	if v6 {
		args = append(args, "-6")
	}
	args = append(args, "route", "replace")
	if r.Type != "" && r.Type != "unicast" {
		args = append(args, r.Type)
	}

	if r.Dst == "" || r.Dst == "default" {
		args = append(args, "default")
	} else {
		args = append(args, r.Dst)
	}
	if r.Gateway != "" {
		args = append(args, "via", r.Gateway)
	}
	if r.Dev != "" {
		args = append(args, "dev", r.Dev)
	}
	if r.PrefSrc != "" {
		args = append(args, "src", r.PrefSrc)
	} else if r.Src != "" {
		args = append(args, "src", r.Src)
	}
	if r.Protocol != "" && r.Protocol != "boot" {
		args = append(args, "proto", r.Protocol)
	}
	if r.Scope != "" && r.Scope != "global" && r.Scope != "universe" {
		args = append(args, "scope", r.Scope)
	}
	if r.Metric > 0 {
		args = append(args, "metric", fmt.Sprintf("%d", r.Metric))
	}
	if table := formatTable(r.Table); table != "" && table != "main" && table != "254" {
		args = append(args, "table", table)
	}

	_, err := executor.RunIP(args...)
	return err
}

func formatTable(table any) string {
	switch value := table.(type) {
	case nil:
		return ""
	case string:
		return value
	case float64:
		return fmt.Sprintf("%.0f", value)
	default:
		return fmt.Sprint(value)
	}
}

func colorizeState(s string) string {
	upper := strings.ToUpper(s)
	switch upper {
	case "UP":
		return color.BoldGreen(upper)
	case "DOWN":
		return color.BoldRed(upper)
	default:
		return color.BoldYellow(upper)
	}
}

func colorizeAddr(addr string, family string) string {
	if family == "inet6" {
		return color.Blue(addr)
	}
	return color.Yellow(addr)
}

// PrintStatus writes a formatted network status to the writer.
func PrintStatus(w io.Writer) error {
	servers, err := readResolv()
	if err != nil {
		return fmt.Errorf("read resolver configuration: %w", err)
	}
	addrs, err := GetAddresses()
	if err != nil {
		return fmt.Errorf("get addresses: %w", err)
	}
	routes, err := GetRoutes()
	if err != nil {
		return fmt.Errorf("get IPv4 routes: %w", err)
	}
	routes6, err := GetRoutes6()
	if err != nil {
		return fmt.Errorf("get IPv6 routes: %w", err)
	}

	// --- DNS ---
	_, _ = fmt.Fprintf(w, "%s\n", color.Bold("DNS:"))
	if len(servers) == 0 {
		_, _ = fmt.Fprintf(w, "  %s\n", color.Dim("(none)"))
	}
	for _, ns := range servers {
		_, _ = fmt.Fprintf(w, "  nameserver %s\n", color.Cyan(ns))
	}

	// --- Interfaces ---
	_, _ = fmt.Fprintf(w, "\n%s\n", color.Bold("Interfaces:"))
	printed := 0
	for _, entry := range addrs {
		// Header line: name | state | mac (skip state for loopback)
		header := "  " + color.BoldCyan(entry.IfName)

		if entry.IfName != "lo" {
			stateBytes, _ := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/operstate", entry.IfName))
			opState := strings.TrimSpace(string(stateBytes))
			if opState == "" {
				opState = "unknown"
			}
			header += fmt.Sprintf(" %s %s", color.Gray("|"), colorizeState(opState))
		}

		macBytes, _ := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/address", entry.IfName))
		mac := strings.TrimSpace(string(macBytes))
		if mac != "" && mac != "00:00:00:00:00:00" {
			header += fmt.Sprintf(" %s %s", color.Gray("|"), color.Gray(mac))
		}
		_, _ = fmt.Fprintln(w, header)

		// Address lines
		for _, a := range entry.AddrInfo {
			cidr := fmt.Sprintf("%s/%d", a.Local, a.PrefixLen)
			suffix := ""
			if a.Tentative {
				suffix = color.BoldYellow(" (tentative)")
			}
			if a.Dynamic {
				suffix += color.Dim(" dynamic")
			}
			if a.Scope == "link" {
				suffix += color.Dim(" link-local")
			}
			_, _ = fmt.Fprintf(w, "    %s %s%s\n",
				color.Gray("⤷"),
				colorizeAddr(cidr, a.Family),
				suffix)
		}

		printed++
		// Blank line between interfaces (except last)
		if printed < len(addrs)-1 {
			_, _ = fmt.Fprintln(w)
		}
	}

	// --- IPv4 Routes ---
	_, _ = fmt.Fprintf(w, "\n%s\n", color.Bold("Routes:"))
	for _, r := range routes {
		_, _ = fmt.Fprintln(w, formatRoute(r))
	}

	// --- IPv6 Routes ---
	if len(routes6) > 0 {
		_, _ = fmt.Fprintf(w, "\n%s\n", color.Bold("IPv6 Routes:"))
		for _, r := range routes6 {
			_, _ = fmt.Fprintln(w, formatRoute(r))
		}
	}
	return nil
}

func formatRoute(r Route) string {
	dst := r.Dst
	if dst == "" {
		dst = "default"
	}
	line := "  " + color.Bold(dst)
	if r.Gateway != "" {
		line += " via " + color.Yellow(r.Gateway)
	}
	if r.Dev != "" {
		line += " dev " + color.Cyan(r.Dev)
	}
	if r.Protocol != "" && r.Protocol != "boot" && r.Protocol != "kernel" {
		line += color.Dim(" proto " + r.Protocol)
	}
	if r.Scope != "" && r.Scope != "global" && r.Scope != "universe" {
		line += color.Dim(" scope " + r.Scope)
	}
	return line
}

func readResolv() ([]string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver ") {
			ns := strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
			if ns != "" {
				servers = append(servers, ns)
			}
		}
	}
	return servers, nil
}
