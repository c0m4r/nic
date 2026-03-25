package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestTokenize(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"ip link set eth0 up", []string{"ip", "link", "set", "eth0", "up"}},
		{"  ip  a  a  10.0.0.1/24  dev  lo  ", []string{"ip", "a", "a", "10.0.0.1/24", "dev", "lo"}},
		{`wifi "My Network" secret`, []string{"wifi", "My Network", "secret"}},
		{`wifi 'My Network' secret`, []string{"wifi", "My Network", "secret"}},
		{"ns 1.1.1.1", []string{"ns", "1.1.1.1"}},
		{"", nil},
		{"   ", nil},
	}

	for _, tt := range tests {
		got := tokenize(tt.input)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("tokenize(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.0.1", true},
		{"192.168.0.1/24", true},
		{"10.0.0.0/8", true},
		{"::1", true},
		{"::1/128", true},
		{"fd76:1e4b:375a::/48", true},
		{"fe80::1", true},
		{"eth0", false},
		{"link", false},
		{"up", false},
		{"default", false},
		{"bond0.100", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isIPAddress(tt.input)
		if got != tt.want {
			t.Errorf("isIPAddress(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestEnsureCIDR(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.0.1/24", "192.168.0.1/24"},
		{"192.168.0.1", "192.168.0.1/32"},
		{"10.0.0.1", "10.0.0.1/32"},
		{"::1/128", "::1/128"},
		{"::1", "::1/128"},
		{"fd76:1e4b:375a::", "fd76:1e4b:375a::/128"},
		{"fd76:1e4b:375a::/48", "fd76:1e4b:375a::/48"},
	}

	for _, tt := range tests {
		got := ensureCIDR(tt.input)
		if got != tt.want {
			t.Errorf("ensureCIDR(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseLine(t *testing.T) {
	tests := []struct {
		line    string
		wantTyp CmdType
		wantErr bool
	}{
		// Full iproute2
		{"ip link set eth0 up", CmdIPRoute2, false},
		{"ip address add 10.0.0.1/24 dev eth0", CmdIPRoute2, false},
		{"ip route add default via 192.168.0.1 dev eth0", CmdIPRoute2, false},

		// Abbreviated iproute2
		{"ip l s eth0 up", CmdIPRoute2, false},
		{"ip a a 10.0.0.1/24 dev eth0", CmdIPRoute2, false},
		{"ip r a default via 192.168.0.1", CmdIPRoute2, false},

		// IP shortcut
		{"ip 192.168.0.1/24 eth0", CmdIPShortcut, false},
		{"ip 192.168.0.1 eth0", CmdIPShortcut, false},
		{"ip fd76:1e4b:375a::/48 eth0", CmdIPShortcut, false},
		{"ip ::1/128 lo", CmdIPShortcut, false},

		// Interface shortcut
		{"if eth0 up", CmdIfShortcut, false},
		{"if eth0 down", CmdIfShortcut, false},

		// Up/down shortcut
		{"up eth0", CmdIfShortcut, false},
		{"down eth0", CmdIfShortcut, false},

		// Route shortcut
		{"route default via 192.168.0.1 eth0", CmdRouteShortcut, false},
		{"route 10.0.0.0/8 via 192.168.0.1 eth0", CmdRouteShortcut, false},
		{"route 10.0.0.0/8 eth0", CmdRouteShortcut, false},

		// Directives
		{"alias my_eth enp14s0", CmdAlias, false},
		{"pin my_eth aa:bb:cc:dd:ee:ff", CmdPin, false},
		{"nameserver 1.1.1.1", CmdNameserver, false},
		{"ns 8.8.8.8", CmdNameserver, false},
		{"wifi MySSID MyPassword", CmdWifi, false},
		{"wifi MySSID MyPassword wlan0", CmdWifi, false},
		{"dhcp eth0", CmdDHCP, false},
		{"dhcp eth0 dhclient", CmdDHCP, false},
		{"include /etc/nic.d/*.conf", CmdInclude, false},

		// Errors
		{"alias", CmdAlias, true},
		{"pin x", CmdPin, true},
		{"if eth0", CmdIfShortcut, true},
		{"up", CmdIfShortcut, true},
		{"route x", CmdRouteShortcut, true},
		{"ns", CmdNameserver, true},
		{"wifi x", CmdWifi, true},
		{"dhcp", CmdDHCP, true},
		{"include", CmdInclude, true},
		{"bogus command", CmdIPRoute2, true},
	}

	for _, tt := range tests {
		cmd, err := parseLine(tt.line, "test.conf", 1)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseLine(%q): expected error, got nil", tt.line)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseLine(%q): unexpected error: %v", tt.line, err)
			continue
		}
		if cmd.Type != tt.wantTyp {
			t.Errorf("parseLine(%q).Type = %d, want %d", tt.line, cmd.Type, tt.wantTyp)
		}
	}
}

func TestUpDownNormalization(t *testing.T) {
	cmd, err := parseLine("up eth0", "test.conf", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Type != CmdIfShortcut {
		t.Errorf("type = %d, want CmdIfShortcut", cmd.Type)
	}
	// Should be normalized to: if eth0 up
	want := []string{"if", "eth0", "up"}
	if !reflect.DeepEqual(cmd.Tokens, want) {
		t.Errorf("tokens = %v, want %v", cmd.Tokens, want)
	}

	cmd, err = parseLine("down bond0", "test.conf", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want = []string{"if", "bond0", "down"}
	if !reflect.DeepEqual(cmd.Tokens, want) {
		t.Errorf("tokens = %v, want %v", cmd.Tokens, want)
	}
}

func TestExpandCommand(t *testing.T) {
	tests := []struct {
		name string
		cmd  Command
		want []string
	}{
		{
			"iproute2 passthrough",
			Command{Type: CmdIPRoute2, Tokens: []string{"ip", "link", "set", "eth0", "up"}},
			[]string{"link", "set", "eth0", "up"},
		},
		{
			"if shortcut",
			Command{Type: CmdIfShortcut, Tokens: []string{"if", "eth0", "up"}},
			[]string{"link", "set", "eth0", "up"},
		},
		{
			"ip shortcut with cidr",
			Command{Type: CmdIPShortcut, Tokens: []string{"ip", "192.168.0.1/24", "eth0"}},
			[]string{"address", "add", "192.168.0.1/24", "dev", "eth0"},
		},
		{
			"ip shortcut without cidr (ipv4)",
			Command{Type: CmdIPShortcut, Tokens: []string{"ip", "10.0.0.1", "eth0"}},
			[]string{"address", "add", "10.0.0.1/32", "dev", "eth0"},
		},
		{
			"ip shortcut ipv6",
			Command{Type: CmdIPShortcut, Tokens: []string{"ip", "fd76:1e4b:375a::/48", "eth0"}},
			[]string{"address", "add", "fd76:1e4b:375a::/48", "dev", "eth0"},
		},
		{
			"ip shortcut ipv6 bare",
			Command{Type: CmdIPShortcut, Tokens: []string{"ip", "::1", "lo"}},
			[]string{"address", "add", "::1/128", "dev", "lo"},
		},
		{
			"alias returns nil",
			Command{Type: CmdAlias, Tokens: []string{"alias", "x", "y"}},
			nil,
		},
		{
			"nameserver returns nil",
			Command{Type: CmdNameserver, Tokens: []string{"nameserver", "1.1.1.1"}},
			nil,
		},
	}

	for _, tt := range tests {
		got := ExpandCommand(tt.cmd)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: ExpandCommand() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestExpandRouteShortcut(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			"default via gw iface",
			[]string{"default", "via", "192.168.0.1", "eth0"},
			[]string{"route", "add", "default", "via", "192.168.0.1", "dev", "eth0"},
		},
		{
			"dest via gw iface",
			[]string{"10.0.0.0/8", "via", "192.168.0.1", "eth0"},
			[]string{"route", "add", "10.0.0.0/8", "via", "192.168.0.1", "dev", "eth0"},
		},
		{
			"dest iface (no via)",
			[]string{"10.0.0.0/8", "eth0"},
			[]string{"route", "add", "10.0.0.0/8", "dev", "eth0"},
		},
		{
			"already has dev keyword",
			[]string{"10.0.0.0/8", "via", "192.168.0.1", "dev", "eth0"},
			[]string{"route", "add", "10.0.0.0/8", "via", "192.168.0.1", "dev", "eth0"},
		},
	}

	for _, tt := range tests {
		got := expandRouteShortcut(tt.args)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: expandRouteShortcut(%v) = %v, want %v", tt.name, tt.args, got, tt.want)
		}
	}
}

func TestExpandCommandString(t *testing.T) {
	tests := []struct {
		cmd  Command
		want string
	}{
		{
			Command{Type: CmdIPRoute2, Raw: "ip l s eth0 up"},
			"ip l s eth0 up",
		},
		{
			Command{Type: CmdIfShortcut, Tokens: []string{"if", "eth0", "up"}},
			"ip link set eth0 up",
		},
		{
			Command{Type: CmdIPShortcut, Tokens: []string{"ip", "192.168.0.1", "eth0"}},
			"ip address add 192.168.0.1/32 dev eth0",
		},
		{
			Command{Type: CmdNameserver, Tokens: []string{"ns", "1.1.1.1"}},
			"nameserver 1.1.1.1",
		},
		{
			Command{Type: CmdAlias, Tokens: []string{"alias", "my_eth", "enp14s0"}},
			"alias my_eth → enp14s0",
		},
		{
			Command{Type: CmdPin, Tokens: []string{"pin", "my_eth", "aa:bb:cc:dd:ee:ff"}},
			"pin my_eth → MAC aa:bb:cc:dd:ee:ff",
		},
		{
			Command{Type: CmdDHCP, Tokens: []string{"dhcp", "eth0"}},
			"dhcp eth0",
		},
		{
			Command{Type: CmdDHCP, Tokens: []string{"dhcp", "eth0", "dhclient"}},
			"dhcp eth0 using dhclient",
		},
	}

	for _, tt := range tests {
		got := ExpandCommandString(tt.cmd)
		if got != tt.want {
			t.Errorf("ExpandCommandString(%v) = %q, want %q", tt.cmd.Type, got, tt.want)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()

	// Create main config
	mainConf := filepath.Join(dir, "nic.conf")
	subDir := filepath.Join(dir, "nic.d")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainContent := `# Main config
alias my_eth eth0
if my_eth up
ip 192.168.0.1/24 my_eth
include nic.d/*.conf
ns 1.1.1.1
`
	if err := os.WriteFile(mainConf, []byte(mainContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create included config
	subContent := `route default via 192.168.0.1 my_eth
ns 8.8.8.8
`
	if err := os.WriteFile(filepath.Join(subDir, "routes.conf"), []byte(subContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(mainConf)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// Should have: alias + if + ip + route (from include) + ns (from include) + ns
	// = 6 commands
	if len(cfg.Commands) != 6 {
		t.Errorf("got %d commands, want 6", len(cfg.Commands))
		for i, c := range cfg.Commands {
			t.Logf("  [%d] type=%d tokens=%v file=%s", i, c.Type, c.Tokens, c.File)
		}
	}

	// Verify include was resolved relative to config dir
	if len(cfg.Commands) >= 4 {
		routeCmd := cfg.Commands[3]
		if routeCmd.Type != CmdRouteShortcut {
			t.Errorf("command[3] type = %d, want CmdRouteShortcut", routeCmd.Type)
		}
	}
}

func TestLoadConfigInlineComments(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "test.conf")

	content := `ip 10.0.0.1/24 eth0 # this is a comment
ns 1.1.1.1 # dns
`
	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(confPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(cfg.Commands) != 2 {
		t.Fatalf("got %d commands, want 2", len(cfg.Commands))
	}

	// The ip shortcut should have 3 tokens (ip, addr, iface), not including the comment
	if len(cfg.Commands[0].Tokens) != 3 {
		t.Errorf("command[0] tokens = %v, want 3 tokens", cfg.Commands[0].Tokens)
	}
}

func TestNaturalLess(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"1.conf", "2.conf", true},
		{"2.conf", "10.conf", true},
		{"10.conf", "2.conf", false},
		{"a1.conf", "a2.conf", true},
		{"a2.conf", "a10.conf", true},
		{"a10.conf", "a2.conf", false},
		{"foo", "foo", false},
		{"", "a", true},
		{"a", "", false},
	}

	for _, tt := range tests {
		got := naturalLess(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("naturalLess(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
