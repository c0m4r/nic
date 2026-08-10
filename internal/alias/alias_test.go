package alias

import (
	"reflect"
	"testing"
)

func TestAddAlias(t *testing.T) {
	mgr := NewManager()
	mgr.AddAlias("my_eth", "enp14s0")
	mgr.AddAlias("mgmt", "eth0")
	mgr.AddAlias("default", "wan0")
	mgr.AddAlias("up", "lan0")

	// Resolve without any pins should succeed
	if err := mgr.Resolve(); err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}

	if got, ok := mgr.Get("my_eth"); !ok || got != "enp14s0" {
		t.Errorf("Get(my_eth) = %q, %v, want enp14s0, true", got, ok)
	}
	if got, ok := mgr.Get("mgmt"); !ok || got != "eth0" {
		t.Errorf("Get(mgmt) = %q, %v, want eth0, true", got, ok)
	}
	if _, ok := mgr.Get("nonexistent"); ok {
		t.Error("Get(nonexistent) should return false")
	}
}

func TestResolveInTokens(t *testing.T) {
	mgr := NewManager()
	mgr.AddAlias("my_eth", "enp14s0")
	mgr.AddAlias("mgmt", "eth0")
	mgr.AddAlias("default", "wan0")
	mgr.AddAlias("up", "lan0")
	_ = mgr.Resolve()

	tests := []struct {
		input []string
		want  []string
	}{
		{
			[]string{"link", "set", "my_eth", "up"},
			[]string{"link", "set", "enp14s0", "up"},
		},
		{
			[]string{"address", "add", "192.168.0.1/24", "dev", "mgmt"},
			[]string{"address", "add", "192.168.0.1/24", "dev", "eth0"},
		},
		{
			[]string{"link", "set", "eth1", "up"},
			[]string{"link", "set", "eth1", "up"},
		},
		{
			[]string{"route", "add", "default", "via", "192.0.2.1", "dev", "default"},
			[]string{"route", "add", "default", "via", "192.0.2.1", "dev", "wan0"},
		},
		{
			[]string{"link", "set", "up", "up"},
			[]string{"link", "set", "lan0", "up"},
		},
		{
			[]string{"link", "add", "link", "default", "name", "up", "type", "vlan", "id", "10"},
			[]string{"link", "add", "link", "wan0", "name", "up", "type", "vlan", "id", "10"},
		},
		{
			[]string{"rule", "add", "iif", "default", "oif", "up", "priority", "100"},
			[]string{"rule", "add", "iif", "wan0", "oif", "lan0", "priority", "100"},
		},
		{
			[]string{},
			[]string{},
		},
	}

	for _, tt := range tests {
		got := mgr.ResolveInTokens(tt.input)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ResolveInTokens(%v) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestPinWithoutInterface(t *testing.T) {
	mgr := NewManager()
	// Pin a MAC that won't exist on the test system
	mgr.AddPin("test_if", "ff:ff:ff:ff:ff:ff")

	err := mgr.Resolve()
	if err == nil {
		t.Error("Resolve() should error when MAC not found")
	}
}
