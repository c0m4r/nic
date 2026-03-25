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

// ResolveInTokens replaces any token matching a known alias/pin name with
// the actual interface name.
func (m *Manager) ResolveInTokens(tokens []string) []string {
	out := make([]string, len(tokens))
	for i, tok := range tokens {
		if resolved, ok := m.resolved[tok]; ok {
			out[i] = resolved
		} else {
			out[i] = tok
		}
	}
	return out
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
