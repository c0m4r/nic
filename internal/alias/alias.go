package alias

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Manager struct {
	aliases  map[string]string // name → interface name
	pins     map[string]string // name → MAC address
	resolved map[string]string // combined resolved map: name → actual interface
}

func NewManager() *Manager {
	return &Manager{
		aliases:  make(map[string]string),
		pins:     make(map[string]string),
		resolved: make(map[string]string),
	}
}

func (m *Manager) AddAlias(name, iface string) {
	m.aliases[name] = iface
}

func (m *Manager) AddPin(name, mac string) {
	m.pins[name] = strings.ToLower(mac)
}

// Resolve resolves all pins by looking up current interfaces by MAC address,
// and merges with static aliases into the resolved map.
func (m *Manager) Resolve() error {
	m.resolved = make(map[string]string)

	// Copy static aliases
	for name, iface := range m.aliases {
		m.resolved[name] = iface
	}

	// Resolve pins by MAC
	for name, mac := range m.pins {
		iface, err := findInterfaceByMAC(mac)
		if err != nil {
			return fmt.Errorf("pin %q (MAC %s): %w", name, mac, err)
		}
		m.resolved[name] = iface
	}

	return nil
}

// ResolveInTokens replaces aliases only where iproute2 expects an interface
// name. Replacing every matching token corrupts literals such as a route's
// "default" destination or a link-state "up" when those happen to be aliases.
func (m *Manager) ResolveInTokens(tokens []string) []string {
	out := make([]string, len(tokens))
	copy(out, tokens)

	objectIndex, ok := ipObjectIndex(out)
	if !ok {
		return out
	}

	switch canonicalIPObject(out[objectIndex]) {
	case "link":
		m.resolveLinkInterfaces(out, objectIndex)
	case "address", "route":
		resolveAfterKeywords(out, m.resolveToken, "dev")
	case "rule":
		resolveAfterKeywords(out, m.resolveToken, "iif", "oif")
	}
	return out
}

func (m *Manager) resolveLinkInterfaces(tokens []string, objectIndex int) {
	action := canonicalIPAction(tokens[objectIndex+1])
	switch action {
	case "set", "delete":
		position := objectIndex + 2
		if position < len(tokens) && tokens[position] == "dev" {
			position++
		}
		if position < len(tokens) {
			m.resolveToken(tokens, position)
		}
		// The only additional interface value supported by nic's rollback-safe
		// link settings is "master <interface>".
		resolveAfterKeywords(tokens, m.resolveToken, "master")
	case "add":
		// link add link <parent> name <new-name> ...: parent is an
		// interface reference, while the new interface name is a literal.
		for i := objectIndex + 2; i+1 < len(tokens); i++ {
			if tokens[i] == "link" {
				m.resolveToken(tokens, i+1)
			}
		}
	}
}

func (m *Manager) resolveToken(tokens []string, index int) {
	if resolved, ok := m.resolved[tokens[index]]; ok {
		tokens[index] = resolved
	}
}

func resolveAfterKeywords(tokens []string, resolve func([]string, int), keywords ...string) {
	for i := 0; i+1 < len(tokens); i++ {
		for _, keyword := range keywords {
			if tokens[i] == keyword {
				resolve(tokens, i+1)
				break
			}
		}
	}
}

func ipObjectIndex(tokens []string) (int, bool) {
	index := 0
	for index < len(tokens) && (tokens[index] == "-4" || tokens[index] == "-6") {
		index++
	}
	return index, index+1 < len(tokens)
}

func canonicalIPObject(word string) string {
	if word == "r" || strings.HasPrefix("route", word) {
		return "route"
	}
	if strings.HasPrefix("rule", word) {
		return "rule"
	}
	if strings.HasPrefix("link", word) {
		return "link"
	}
	if strings.HasPrefix("address", word) || strings.HasPrefix("addr", word) {
		return "address"
	}
	return word
}

func canonicalIPAction(word string) string {
	switch {
	case strings.HasPrefix("set", word):
		return "set"
	case strings.HasPrefix("add", word):
		return "add"
	case strings.HasPrefix("delete", word), strings.HasPrefix("del", word):
		return "delete"
	default:
		return word
	}
}

// Get returns the resolved interface name for an alias/pin, if known.
func (m *Manager) Get(name string) (string, bool) {
	v, ok := m.resolved[name]
	return v, ok
}

func findInterfaceByMAC(mac string) (string, error) {
	mac = strings.ToLower(mac)
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", fmt.Errorf("cannot read /sys/class/net: %w", err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join("/sys/class/net", entry.Name(), "address"))
		if err != nil {
			continue
		}
		if strings.ToLower(strings.TrimSpace(string(data))) == mac {
			return entry.Name(), nil
		}
	}
	return "", fmt.Errorf("no interface found with MAC %s", mac)
}
