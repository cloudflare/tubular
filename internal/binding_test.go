package internal

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBinding(t *testing.T) {
	valid := []struct {
		prefix  string
		ip      string
		maskLen int
	}{
		{"127.0.0.1", "127.0.0.1", 32},
		{"127.0.0.1/32", "127.0.0.1", 32},
		{"127.0.0.1/8", "127.0.0.0", 8},
		{"fd00::1/64", "fd00::", 64},
		{"fd00::1", "fd00::1", 128},
		{"::ffff:127.0.0.1/64", "::", 64},
		{"::ffff:127.0.0.1/128", "127.0.0.1", 32},
		{"::ffff:127.0.0.1", "127.0.0.1", 32},
		{"::ffff:7f00:1/104", "127.0.0.0", 8},
		{"0.0.0.0", "0.0.0.0", 32},
		{"::", "::", 128},
		{"0.0.0.0/0", "0.0.0.0", 0},
		{"::/0", "::", 0},
	}

	for _, tc := range valid {
		t.Run(tc.prefix, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)

			bind, err := NewBinding(UDP, tc.prefix, 80)
			if err != nil {
				t.Fatal("Can't create binding:", tc.prefix, err)
			}

			if !bind.Prefix.IP.Equal(ip) {
				t.Errorf("Binding IP doesn't match: %s != %s", bind.Prefix.IP, ip)
			}

			ones, bits := bind.Prefix.Mask.Size()
			if ones == 0 && bits == 0 {
				t.Error("Invalid prefix mask")
			}
			if ones != tc.maskLen {
				t.Errorf("Binding mask has wrong length: %d != %d", ones, tc.maskLen)
			}
		})
	}

	invalid := []string{
		"127.1",
		"127.0.0.1/",
		"",
	}

	for _, tc := range invalid {
		t.Run(tc, func(t *testing.T) {
			bind, err := NewBinding(TCP, tc, 8080)
			if err == nil {
				t.Logf("%+v", bind)
				t.Error("Accepted invalid prefix")
			}
		})
	}

	in, err := NewBinding(TCP, "127.0.0.1", 80)
	if err != nil {
		t.Fatal("Can't create binding:", err)
	}

	buf, err := in.MarshalBinary()
	if err != nil {
		t.Fatal("Can't marshal binding:", err)
	}

	out := &Binding{}
	if err := out.UnmarshalBinary(buf); err != nil {
		t.Fatal("Can't unmarshal binding: err")
	}

	if diff := cmp.Diff(in, out); diff != "" {
		t.Errorf("Decoded binding doesn't match input (-want +got):\n%s", diff)
	}
}

func TestCopyBinding(t *testing.T) {
	bind, err := NewBinding(UDP, "127.0.0.1", 80)
	if err != nil {
		t.Fatal(err)
	}

	cpy := bind.copy()
	if cpy.Prefix == bind.Prefix {
		t.Error("copy should create a new Prefix")
	}
}
