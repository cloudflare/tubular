package internal

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"code.cfops.it/sys/tubular/internal/log"
	"code.cfops.it/sys/tubular/internal/testutil"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestLoadDispatcher(t *testing.T) {
	netns := testutil.NewNetNS(t)

	dp := mustCreateDispatcher(t, nil, netns.Path())
	if err := dp.Close(); err != nil {
		t.Fatal("Can't close dispatcher:", err)
	}

	if _, err := os.Stat(dp.Path); err != nil {
		t.Error("State directory doesn't exist:", err)
	}
}

func TestUnloadDispatcher(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, nil, netns.Path())

	dir, err := os.Open(dp.Path)
	if err != nil {
		t.Fatal("Open state directory:", err)
	}
	defer dir.Close()

	entries, err := dir.ReadDir(0)
	if err != nil {
		t.Fatal("Read state entries:", err)
	}
	if len(entries) == 0 {
		t.Fatal("No entries in state directory")
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	entry := entries[rng.Intn(len(entries))]
	path := filepath.Join(dp.Path, entry.Name())

	t.Log("Removing", path)
	if err := os.RemoveAll(path); err != nil {
		t.Fatal("Remove state entry:", err)
	}

	dp.Close()

	if err := UnloadDispatcher(netns.Path(), "/sys/fs/bpf"); err != nil {
		t.Fatal("Unload corrupt dispatcher:", err)
	}

	if _, err := os.Stat(dp.Path); err == nil {
		t.Error("State directory exists after unload")
	}
}

func TestUnloadDispatcherNotLoaded(t *testing.T) {
	netns := testutil.NewNetNS(t)

	err := UnloadDispatcher(netns.Path(), "/sys/fs/bpf")
	if !errors.Is(err, ErrNotLoaded) {
		t.Fatal("Expected ErrNotLoaded, got", err)
	}
}

func TestDispatcherLocking(t *testing.T) {
	procs := runtime.GOMAXPROCS(0)
	if procs < 2 {
		t.Error("Need GOMAXPROCS >= 2")
	}

	netns := testutil.NewNetNS(t)
	netnsPath := netns.Path()
	done := make(chan struct{}, procs-1)
	open := func() {
		for {
			dp, err := OpenDispatcher(log.Discard, netnsPath, "/sys/fs/bpf")
			if errors.Is(err, ErrNotLoaded) {
				continue
			}
			if err != nil {
				t.Error("Can't open dispatcher:", err)
				break
			}
			dp.Close()
			break
		}

		done <- struct{}{}
	}

	for i := 0; i < procs-1; i++ {
		go open()
	}

	time.Sleep(50 * time.Millisecond)

	mustCreateDispatcher(t, nil, netnsPath)

	if _, err := CreateDispatcher(log.Discard, netnsPath, "/sys/fs/bpf"); !errors.Is(err, ErrLoaded) {
		t.Fatal("Creating an existing dispatcher doesn't return ErrLoaded:", err)
	}

	timeout := time.After(time.Second)
	for i := 0; i < procs-1; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("Can't open multiple dispatchers")
		}
	}
}

func TestAddAndRemoveBindings(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, nil, netns.Path())

	testcases := []struct {
		ip string
		*Binding
	}{
		{"127.0.0.1", mustNewBinding(t, "foo", TCP, "127.0.0.0/8", 8080)},
		{"127.0.0.1", mustNewBinding(t, "foo", UDP, "127.0.0.0/8", 8080)},
		{"[::1]", mustNewBinding(t, "foo", TCP, "::1", 8080)},
		{"[::1]", mustNewBinding(t, "foo", UDP, "::1", 8080)},
	}

	for _, tc := range testcases {
		name := fmt.Sprintf("%v %s", tc.Protocol, tc.Prefix)
		t.Run(name, func(t *testing.T) {
			network := tc.Protocol.String()
			testutil.ListenAndEcho(t, netns, network, tc.ip+":8080")

			if !testutil.CanDial(t, netns, network, tc.ip+":8080") {
				t.Fatal("Can't dial before creating the binding")
			}

			err := dp.AddBinding(tc.Binding)
			if err != nil {
				t.Fatal("Can't create binding:", err)
			}

			if testutil.CanDial(t, netns, network, tc.ip+":8080") {
				t.Fatal("Binding without registered service doesn't refuse connections")
			}

			err = dp.RemoveBinding(tc.Binding)
			if err != nil {
				t.Fatal("Can't remove binding:", err)
			}

			if !testutil.CanDial(t, netns, network, tc.ip+":8080") {
				t.Fatal("Can't dial after removing the binding")
			}
		})
	}
}

func TestBindingWithEmptyLabel(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, nil, netns.Path())

	if err := dp.AddBinding(mustNewBinding(t, "", TCP, "::1", 80)); err == nil {
		t.Fatal("AddBinding accepts empty label")
	}

	if err := dp.RemoveBinding(mustNewBinding(t, "", TCP, "::1", 80)); err == nil {
		t.Fatal("RemoveBinding accepts empty label")
	}
}

func TestUpdateBinding(t *testing.T) {
	foo := mustNewBinding(t, "foo", TCP, "127.0.0.0/8", 8080)
	bar := mustNewBinding(t, "bar", TCP, "127.0.0.0/8", 8080)
	bar32 := mustNewBinding(t, "bar", TCP, "127.0.0.0/32", 8080)
	fooDest := newDestinationFromBinding(foo)
	barDest := newDestinationFromBinding(bar)

	testcases := []struct {
		name          string
		first, second *Binding
		result        []*Destination
	}{
		{"overwrite", foo, bar, []*Destination{barDest}},
		{"more specific", foo, bar32, []*Destination{fooDest, barDest}},
		{"less specific", bar32, foo, []*Destination{fooDest, barDest}},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			netns := testutil.NewNetNS(t)
			dp := mustCreateDispatcher(t, nil, netns.Path())

			if err := dp.AddBinding(test.first); err != nil {
				t.Fatal(err)
			}

			if err := dp.AddBinding(test.second); err != nil {
				t.Fatal(err)
			}

			checkDestinations(t, dp.destinations, test.result...)
		})
	}
}

func TestRemoveBinding(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, nil, netns.Path())
	bindA := mustNewBinding(t, "foo", TCP, "::1", 80)
	bindB := mustNewBinding(t, "bar", TCP, "::1", 80)

	if err := dp.RemoveBinding(bindA); err == nil {
		t.Error("Removing a non-existing binding doesn't return an error")
	}

	if err := dp.AddBinding(bindA); err != nil {
		t.Fatal(err)
	}

	dests, err := dp.destinations.List()
	if err != nil {
		t.Fatal(err)
	}

	if n := len(dests); n != 1 {
		t.Fatal("Expected one destination, got", n)
	}

	if err := dp.RemoveBinding(bindB); err == nil {
		t.Fatal("Removed a binding where the destination doesn't match")
	}

	if err := dp.RemoveBinding(bindA); err != nil {
		t.Fatal("Can't remove binding:", err)
	}

	dests, err = dp.destinations.List()
	if err != nil {
		t.Fatal(err)
	}

	if n := len(dests); n != 0 {
		t.Fatal("Expected no destinations, got", n)
	}
}

func TestReplaceBindings(t *testing.T) {
	a := mustNewBinding(t, "foo", TCP, "::1", 80)
	aRelabeled := mustNewBinding(t, "bar", TCP, "::1", 80)
	b := mustNewBinding(t, "bar", UDP, "127.0.0.1", 42)

	t.Run("multiple labels", func(t *testing.T) {
		netns := testutil.NewNetNS(t)
		dp := mustCreateDispatcher(t, nil, netns.Path())

		if _, err := dp.ReplaceBindings(Bindings{a, aRelabeled}); err == nil {
			t.Error("ReplaceBindings doesn't reject multiple labels for the same binding")
		}
	})

	testcases := []struct {
		initial, replacement Bindings
	}{
		{nil, nil},
		{nil, Bindings{a}},
		{Bindings{a}, Bindings{a}},
		{nil, Bindings{a, b}},
		{Bindings{a}, Bindings{b}},
		{Bindings{a}, Bindings{aRelabeled}},
		{Bindings{a, b}, nil},
	}

	for _, test := range testcases {
		name := fmt.Sprintf("%v->%v", test.initial, test.replacement)
		t.Run(name, func(t *testing.T) {
			netns := testutil.NewNetNS(t)
			output := new(log.Buffer)
			dp := mustCreateDispatcher(t, output, netns.Path())

			for _, bind := range test.initial {
				if err := dp.AddBinding(bind); err != nil {
					t.Fatal(err)
				}
			}

			output.Reset()
			changed, err := dp.ReplaceBindings(test.replacement)
			if err != nil {
				t.Fatal("ReplaceBindings failed:", err)
			}

			if changed && output.Len() == 0 {
				t.Error("No output generated even though changes were made")
			} else if !changed && output.Len() > 0 {
				t.Error("Generated output even though no changes were made")
				t.Log(output.String())
			}

			have, err := dp.Bindings()
			if err != nil {
				t.Fatal(err)
			}

			sort := cmpopts.SortSlices(func(a, b *Binding) bool {
				return a.Label < b.Label
			})

			if diff := cmp.Diff(test.replacement, have, sort); diff != "" {
				t.Errorf("bindings don't match (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRegisterSupportedSocketKind(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, nil, netns.Path())

	networks := []string{
		"tcp4",
		"tcp6",
		"udp4",
		"udp6",
	}
	for _, network := range networks {
		t.Run(network, func(t *testing.T) {
			conn := testutil.Listen(t, netns, network, "")
			_, created, err := dp.RegisterSocket("service-name", conn)
			if err != nil {
				t.Fatal("RegisterSocket failed:", err)
			}

			if !created {
				t.Error("RegisterSocket doesn't return true for new sockets")
			}

			// TODO: Lookup registered socket
		})
	}
}

func TestUpdateRegisteredSocket(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, nil, netns.Path())

	for i := 0; i < 3; i++ {
		conn := testutil.Listen(t, netns, "tcp4", "")
		_, created, err := dp.RegisterSocket("service-name", conn)
		if err != nil {
			t.Fatalf("Can't RegisterSocket try #%d: %v", i+1, err)
		}

		if i > 0 && created {
			t.Errorf("Created is true on try #%d", i+1)
		}
	}
}

func TestRegisterUnixSocket(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, nil, netns.Path())

	networks := []string{
		"unix",
		"unixpacket",
		"unixgram",
	}
	for _, network := range networks {
		t.Run(network, func(t *testing.T) {
			conn := testutil.Listen(t, netns, network, "")
			_, _, err := dp.RegisterSocket("service-name", conn)
			if err == nil {
				t.Fatal("RegisterSocket didn't fail")
			}
		})
	}
}

func TestRegisterConnectedSocket(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, nil, netns.Path())

	networks := []string{
		"tcp4",
		"udp4",
	}

	for _, network := range networks {
		t.Run(network, func(t *testing.T) {
			testutil.ListenAndEcho(t, netns, network, "127.0.0.1:1234")
			conn := testutil.Dial(t, netns, network, "127.0.0.1:1234")

			_, _, err := dp.RegisterSocket("service-name", conn)
			if err == nil {
				t.Fatal("RegisterSocket didn't fail")
			}
		})
	}
}

func TestMetrics(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, nil, netns.Path())
	ln := testutil.ListenAndEcho(t, netns, "tcp4", "").(*net.TCPListener)

	bind := mustNewBinding(t, "foo", TCP, "127.0.0.1", 8080)
	if err := dp.AddBinding(bind); err != nil {
		t.Fatal("Can't add binding:", err)
	}

	if testutil.CanDial(t, netns, "tcp4", "127.0.0.1:8080") {
		t.Fatal("Could dial before adding socket")
	}

	mustRegisterSocket(t, dp, "foo", ln)

	if !testutil.CanDial(t, netns, "tcp4", "127.0.0.1:8080") {
		t.Fatal("Can't dial after adding socket")
	}

	dest, err := newDestinationFromConn("foo", ln)
	if err != nil {
		t.Fatal(err)
	}

	metrics, err := dp.Metrics()
	if err != nil {
		t.Fatal("Can't get metrics:", err)
	}

	destMetrics, ok := metrics.Destinations[*dest]
	if !ok {
		t.Fatal("No metrics for", dest)
	}

	if destMetrics.Lookups != 2 {
		t.Error("Expected two packets, got", destMetrics.Lookups)
	}

	if destMetrics.Misses != 1 {
		t.Error("Expected one missing socket packet, got", destMetrics.Misses)
	}

	if destMetrics.ErrorBadSocket != 0 {
		t.Error("Expected no incompatible socket packet, got", destMetrics.ErrorBadSocket)
	}

	// Remove the socket from the sockmap
	ln.Close()

	if err := dp.RemoveBinding(bind); err != nil {
		t.Fatal("Can't remove binding:", err)
	}

	// New binding should re-use ID
	bind2 := mustNewBinding(t, "foo", UDP, "127.0.0.1", 443)
	if err := dp.AddBinding(bind2); err != nil {
		t.Fatal("Can't add second binding:", err)
	}

	dest = newDestinationFromBinding(bind2)
	metrics, err = dp.Metrics()
	if err != nil {
		t.Fatal("Can't get metrics:", err)
	}

	destMetrics, ok = metrics.Destinations[*dest]
	if !ok {
		t.Fatal("No metrics for", dest)
	}

	if destMetrics.Lookups != 0 {
		t.Error("Expected zero packets, got", destMetrics.Lookups)
	}

	if destMetrics.Misses != 0 {
		t.Error("Expected zero missing socket packet, got", destMetrics.Misses)
	}

	if destMetrics.ErrorBadSocket != 0 {
		t.Error("Expected zero incompatible socket packet, got", destMetrics.ErrorBadSocket)
	}
}

func TestBindingPrecedence(t *testing.T) {
	netns := testutil.NewNetNS(t, "1.2.3.0/24", "4.3.2.0/24")
	dp := mustCreateDispatcher(t, nil, netns.Path())

	testcases := []*Binding{
		mustNewBinding(t, "spectrum", TCP, "1.2.3.0/24", 0),
		// Port takes prededence over wildcard.
		mustNewBinding(t, "nginx-ssl", TCP, "1.2.3.0/24", 443),
		// More specific prefix takes precedence.
		mustNewBinding(t, "spectrum", TCP, "1.2.3.4/32", 0),
		// More specific prefix with port takes precedence.
		mustNewBinding(t, "nginx-ssl", TCP, "1.2.3.4/32", 80),
		mustNewBinding(t, "nginx-ssl", TCP, "4.3.2.0/24", 443),
		mustNewBinding(t, "new-tls-thing", TCP, "4.3.2.0/25", 443),
	}

	listeners := make(map[string]syscall.Conn)
	for i, bind := range testcases {
		if err := dp.AddBinding(bind); err != nil {
			t.Fatal("Can't add binding", i, bind, err)
		}

		if listeners[bind.Label] != nil {
			continue
		}

		ln := testutil.ListenAndEchoWithName(t, netns, bind.Protocol.String(), "127.0.0.1:0", bind.Label)
		listeners[bind.Label] = ln

		mustRegisterSocket(t, dp, bind.Label, ln)
	}

	for _, test := range []struct {
		address string
		label   string
	}{
		{"1.2.3.1:80", "spectrum"},
		{"1.2.3.1:81", "spectrum"},
		{"1.2.3.1:443", "nginx-ssl"},
		{"1.2.3.4:443", "spectrum"},
		{"1.2.3.4:80", "nginx-ssl"},
		{"4.3.2.1:443", "new-tls-thing"},
		{"4.3.2.128:443", "nginx-ssl"},
	} {
		testutil.CanDialName(t, netns, "tcp", test.address, test.label)
	}
}

func mustNewBinding(tb testing.TB, label string, proto Protocol, prefix string, port uint16) *Binding {
	tb.Helper()

	bdg, err := NewBinding(label, proto, prefix, port)
	if err != nil {
		tb.Fatal("Can't create binding:", err)
	}

	return bdg
}

func mustAddBinding(tb testing.TB, dp *Dispatcher, bind *Binding) {
	tb.Helper()

	if err := dp.AddBinding(bind); err != nil {
		tb.Fatal("Can't add binding:", err)
	}
}

func mustRegisterSocket(tb testing.TB, dp *Dispatcher, label string, conn syscall.Conn) {
	tb.Helper()

	if _, _, err := dp.RegisterSocket(label, conn); err != nil {
		tb.Fatal("Register socket:", err)
	}
}

func mustCreateDispatcher(tb testing.TB, logger log.Logger, netns string) *Dispatcher {
	tb.Helper()

	if logger == nil {
		logger = log.Discard
	}

	dp, err := CreateDispatcher(logger, netns, "/sys/fs/bpf")
	if err != nil {
		tb.Fatal("Can't create dispatcher:", err)
	}

	tb.Cleanup(func() {
		os.RemoveAll(dp.Path)
		dp.Close()
	})
	return dp
}

func mustOpenDispatcher(tb testing.TB, logger log.Logger, netns string) *Dispatcher {
	tb.Helper()

	if logger == nil {
		logger = log.Discard
	}

	dp, err := OpenDispatcher(logger, netns, "/sys/fs/bpf")
	if err != nil {
		tb.Fatal("Can't open dispatcher:", err)
	}

	return dp
}
