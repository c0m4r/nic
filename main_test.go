package main

import (
	"reflect"
	"testing"
)

func TestReverseIPCommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			"link set up → down",
			[]string{"link", "set", "eth0", "up"},
			[]string{"link", "set", "eth0", "down"},
		},
		{
			"link set down stays down",
			[]string{"link", "set", "eth0", "down"},
			[]string{"link", "set", "eth0", "down"},
		},
		{
			"link add → link del",
			[]string{"link", "add", "bond0", "type", "bond"},
			[]string{"link", "del", "bond0"},
		},
		{
			"address add → address del",
			[]string{"address", "add", "192.168.0.1/24", "dev", "eth0"},
			[]string{"address", "del", "192.168.0.1/24", "dev", "eth0"},
		},
		{
			"route add → route del",
			[]string{"route", "add", "default", "via", "192.168.0.1", "dev", "eth0"},
			[]string{"route", "del", "default", "via", "192.168.0.1", "dev", "eth0"},
		},
		{
			"too short returns nil",
			[]string{"link"},
			nil,
		},
		{
			"unknown returns nil",
			[]string{"neigh", "add", "1.2.3.4"},
			nil,
		},
	}

	for _, tt := range tests {
		got := reverseIPCommand(tt.args)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: reverseIPCommand(%v) = %v, want %v", tt.name, tt.args, got, tt.want)
		}
	}
}
