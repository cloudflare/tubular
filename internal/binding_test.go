package internal

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"code.cfops.it/sys/tubular/internal/testutil"
	"github.com/google/go-cmp/cmp"
	"inet.af/netaddr"
)

func TestBinding(t *testing.T) {
	valid := []struct {
		prefix  string
		ip      string
		maskLen uint8
	}{
		{"127.0.0.1", "127.0.0.1", 32},
		{"127.0.0.1/32", "127.0.0.1", 32},
		{"127.0.0.1/8", "127.0.0.0", 8},
		{"2001:20::1/64", "2001:20::", 64},
		{"2001:20::1", "2001:20::1", 128},
		{"0.0.0.0", "0.0.0.0", 32},
		{"::", "::", 128},
		{"0.0.0.0/0", "0.0.0.0", 0},
		{"::/0", "::", 0},
	}

	for _, tc := range valid {
		t.Run(tc.prefix, func(t *testing.T) {
			ip, err := netaddr.ParseIP(tc.ip)
			if err != nil {
				t.Fatal("Can't parse IP:", tc.ip, err)
			}

			bind, err := NewBinding("foo", UDP, tc.prefix, 80)
			if err != nil {
				t.Fatal("Can't create binding:", tc.prefix, err)
			}

			if bind.Prefix.IP() != ip {
				t.Errorf("Binding IP doesn't match: %s != %s", bind.Prefix.IP(), ip)
			}

			if bind.Prefix.Bits() != tc.maskLen {
				t.Errorf("Binding mask has wrong length: %d != %d", bind.Prefix.Bits(), tc.maskLen)
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
			bind, err := NewBinding("bar", TCP, tc, 8080)
			if err == nil {
				t.Logf("%+v", bind)
				t.Error("Accepted invalid prefix")
			}
		})
	}

	in, err := NewBinding("baz", TCP, "127.0.0.1", 80)
	if err != nil {
		t.Fatal("Can't create binding:", err)
	}

	key := newBindingKey(in)
	if err != nil {
		t.Fatal("Can't create bindingKey:", err)
	}

	out := newBindingFromBPF(in.Label, key)
	if diff := cmp.Diff(in, out, testutil.IPPrefixComparer()); diff != "" {
		t.Errorf("Decoded binding doesn't match input (-want +got):\n%s", diff)
	}
}

func TestBindingsSortMatchesDataplane(t *testing.T) {
	netns := testutil.NewNetNS(t, "192.0.2.0/24", "2001:20::/64")
	dp := mustCreateDispatcher(t, nil, netns)

	labels := []string{"a", "b"}

	for _, label := range labels {
		ln := testutil.ListenAndEchoWithName(t, netns, "tcp4", "", label)
		mustRegisterSocket(t, dp, label, ln)
		ln = testutil.ListenAndEchoWithName(t, netns, "tcp6", "", label)
		mustRegisterSocket(t, dp, label, ln)
	}

	seed := time.Now().UnixNano()
	t.Log("Seed is", seed)
	rng := rand.New(rand.NewSource(seed))

	rng.Shuffle(len(labels), func(i, j int) { labels[i], labels[j] = labels[j], labels[i] })

	// The sort ordering of the labels can hide issues with the implementation.
	// Randomly swap the labels around so we can catch such issues.
	win, lose := labels[0], labels[1]

	tests := []struct {
		name string
		// The less specific binding
		lose *Binding
		// The more specific binding
		win *Binding
	}{
		{
			"port wildcard v4",
			mustNewBinding(t, lose, TCP, "192.0.2.0", 0),
			mustNewBinding(t, win, TCP, "192.0.2.0", 80),
		},
		{
			"port wildcard v6",
			mustNewBinding(t, lose, TCP, "2001:20::", 0),
			mustNewBinding(t, win, TCP, "2001:20::", 80),
		},
		{
			"longer prefix v4",
			mustNewBinding(t, lose, TCP, "192.0.2.0/24", 80),
			mustNewBinding(t, win, TCP, "192.0.2.1", 80),
		},
		{
			"longer prefix v6",
			mustNewBinding(t, lose, TCP, "2001:20::/64", 80),
			mustNewBinding(t, win, TCP, "2001:20::1", 80),
		},
		{
			"prefix tie-breaker v4",
			mustNewBinding(t, lose, TCP, "192.0.2.0/24", 80),
			mustNewBinding(t, win, TCP, "192.0.2.1", 0),
		},
		{
			"prefix tie-breaker v6",
			mustNewBinding(t, lose, TCP, "2001:20::/64", 80),
			mustNewBinding(t, win, TCP, "2001:20::1", 0),
		},
		{
			"double wildcard v4",
			mustNewBinding(t, lose, TCP, "192.0.2.0/24", 0),
			mustNewBinding(t, win, TCP, "192.0.2.1", 0),
		},
		{
			"double wildcard v6",
			mustNewBinding(t, lose, TCP, "2001:20::/64", 0),
			mustNewBinding(t, win, TCP, "2001:20::1", 0),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bindings := Bindings{test.win, test.lose}

			if _, _, err := dp.ReplaceBindings(bindings); err != nil {
				t.Fatal("Can't replace bindings:", err)
			}

			cpy := copyAndShuffleBindings(bindings, rng)

			sort.Sort(cpy)
			if diff := cmp.Diff(bindings, cpy, testutil.IPPrefixComparer()); diff != "" {
				t.Errorf("Order not as expected (-want +got):\n%s", diff)
			}

			addrFmt := "%s:%d"
			if test.win.Prefix.IP().Is6() {
				addrFmt = "[%s]:%d"
			}

			addr := fmt.Sprintf(addrFmt, test.win.Prefix.IP(), 80)
			testutil.CanDialName(t, netns, "tcp", addr, test.win.Label)
		})
	}
}

func TestBindingsSortIsGoodForHumans(t *testing.T) {
	tests := []struct {
		name string
		Bindings
	}{
		{
			"v4 before v6", Bindings{
				mustNewBinding(t, "a", TCP, "127.0.0.1", 1),
				mustNewBinding(t, "a", TCP, "127.0.0.2", 1),
				mustNewBinding(t, "a", TCP, "::1", 1),
				mustNewBinding(t, "a", TCP, "ff::", 1),
			},
		},
		{
			"ports ascending", Bindings{
				mustNewBinding(t, "a", TCP, "127.0.0.1", 1),
				mustNewBinding(t, "a", TCP, "127.0.0.1", 2),
				mustNewBinding(t, "a", TCP, "127.0.0.1", 0),
			},
		},
	}

	seed := time.Now().UnixNano()
	t.Log("Seed is", seed)
	rng := rand.New(rand.NewSource(seed))

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cpy := copyAndShuffleBindings(test.Bindings, rng)

			sort.Sort(cpy)
			if diff := cmp.Diff(test.Bindings, cpy, testutil.IPPrefixComparer()); diff != "" {
				t.Errorf("Order not as expected (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseCIDR(t *testing.T) {
	valid := []struct {
		input    string
		expected netaddr.IPPrefix
	}{
		{"127.0.0.1", netaddr.IPPrefixFrom(netaddr.IPv4(127, 0, 0, 1), 32)},
		{"127.0.0.1/24", netaddr.IPPrefixFrom(netaddr.IPv4(127, 0, 0, 1), 24)},
		{"127.0.0.1/32", netaddr.IPPrefixFrom(netaddr.IPv4(127, 0, 0, 1), 32)},
		{"2001:20::1", netaddr.IPPrefixFrom(netaddr.IPv6Raw([16]byte{0x20, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}), 128)},
		{"2001:20::1/64", netaddr.IPPrefixFrom(netaddr.IPv6Raw([16]byte{0x20, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}), 64)},
		{"2001:20::1/128", netaddr.IPPrefixFrom(netaddr.IPv6Raw([16]byte{0x20, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}), 128)},
		{"0.0.0.0", netaddr.IPPrefixFrom(netaddr.IPv4(0, 0, 0, 0), 32)},
		{"0.0.0.0/0", netaddr.IPPrefixFrom(netaddr.IPv4(0, 0, 0, 0), 0)},
		{"::", netaddr.IPPrefixFrom(netaddr.IPv6Raw([16]byte{}), 128)},
		{"::/0", netaddr.IPPrefixFrom(netaddr.IPv6Raw([16]byte{}), 0)},
	}

	for _, testCase := range valid {
		output, err := ParsePrefix(testCase.input)
		if err != nil {
			t.Errorf("Rejected valid input prefix %s\n", testCase.input)
		}

		if testCase.expected != output {
			t.Errorf("Prefix parsed incorrectly:\nexpected: %v\ngot: %v\n", testCase.expected, output)
		}
	}
}

func copyAndShuffleBindings(bind Bindings, rng *rand.Rand) Bindings {
	cpy := make(Bindings, 0, len(bind))
	for _, b := range bind {
		cpyB := *b
		cpy = append(cpy, &cpyB)
	}
	rng.Shuffle(len(cpy), cpy.Swap)
	return cpy
}
