package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"code.cfops.it/sys/tubular/internal/lock"
	"code.cfops.it/sys/tubular/internal/log"
	"code.cfops.it/sys/tubular/internal/testutil"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/google/go-cmp/cmp"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func init() {
	testutil.EnterUnprivilegedMode()
	rand.Seed(time.Now().UnixNano())
}

func TestLoadDispatcher(t *testing.T) {
	netns := testutil.NewNetNS(t)

	dp := mustCreateDispatcher(t, netns)
	if err := dp.Close(); err != nil {
		t.Fatal("Can't close dispatcher:", err)
	}

	if _, err := os.Stat(dp.Path); err != nil {
		t.Error("State directory doesn't exist:", err)
	}

	err := testutil.WithCapabilities(func() error {
		_, err := CreateDispatcher(netns.Path(), "/sys/fs/bpf")
		return err
	}, CreateCapabilities...)
	if !errors.Is(err, ErrLoaded) {
		t.Fatal("Creating an existing dispatcher doesn't return ErrLoaded:", err)
	}
}

func TestUnloadDispatcher(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns)

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

func TestDispatcherConcurrentAccess(t *testing.T) {
	procs := runtime.GOMAXPROCS(0)
	if procs < 2 {
		t.Error("Need GOMAXPROCS >= 2")
	}

	netns := testutil.NewNetNS(t)
	netnsPath := netns.Path()
	done := make(chan struct{}, procs-1)
	open := func() {
		for {
			dp, err := OpenDispatcher(netnsPath, "/sys/fs/bpf", false)
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

	dp := mustCreateDispatcher(t, netns)
	defer dp.Close()

	select {
	case <-done:
		t.Fatal("Locking does not prevent concurrent access")
	case <-time.After(500 * time.Millisecond):
	}

	if err := dp.Close(); err != nil {
		t.Fatal(err)
	}

	timeout := time.After(time.Second)
	for i := 0; i < procs-1; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("Timed out waiting for serial access to dispatcher")
		}
	}
}

func TestDispatcherUpgrade(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns)
	check := assertDispatcherState(t, dp, netns)
	if err := dp.Close(); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		err := testutil.WithCapabilities(func() error {
			_, err := UpgradeDispatcher(netns.Path(), "/sys/fs/bpf")
			return err
		}, CreateCapabilities...)
		if err != nil {
			t.Fatalf("Upgrade #%d failed with: %s", i, err)
		}
	}

	dp = mustOpenDispatcher(t, nil, netns)
	defer dp.Close()
	check(dp)
}

func TestDispatcherUpgradeFailedLinkUpdate(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns)
	check := assertDispatcherState(t, dp, netns)
	if err := dp.Close(); err != nil {
		t.Fatal(err)
	}

	updateLink := func(*link.NetNsLink, *ebpf.Program) error {
		return errors.New("aborted")
	}

	_, err := upgradeDispatcher(netns.Path(), "/sys/fs/bpf", updateLink)
	if err == nil {
		t.Fatal("Upgrade didn't fail")
	}

	dp = mustOpenDispatcher(t, nil, netns)
	defer dp.Close()
	check(dp)
}

type fileInfo struct {
	Name string
	Mode fs.FileMode
}

func filesInDirectory(tb testing.TB, path string) []fileInfo {
	dir, err := os.Open(path)
	if err != nil {
		tb.Fatal(err)
	}
	defer dir.Close()

	files, err := dir.Readdir(0)
	if err != nil {
		tb.Fatal(err)
	}

	var infos []fileInfo
	for _, file := range files {
		infos = append(infos, fileInfo{file.Name(), file.Mode()})
	}

	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Name < infos[j].Name
	})

	return infos
}

func assertDispatcherState(tb testing.TB, dp *Dispatcher, netns ns.NetNS) func(*Dispatcher) {
	tb.Helper()

	bind := mustNewBinding(tb, "foo", TCP, "127.0.0.1", 443)
	mustAddBinding(tb, dp, bind)

	ln := testutil.ListenAndEchoWithName(tb, netns, "tcp4", "", "service").(*net.TCPListener)
	dest := mustRegisterSocket(tb, dp, "foo", ln)

	metrics, err := dp.Metrics()
	if err != nil {
		tb.Fatal(err)
	}

	filesBefore := filesInDirectory(tb, dp.Path)

	return func(dp *Dispatcher) {
		tb.Helper()

		bindings, err := dp.Bindings()
		if err != nil {
			tb.Fatal(err)
		}

		if diff := cmp.Diff(Bindings{bind}, bindings, testutil.IPPrefixComparer()); diff != "" {
			tb.Errorf("Bindings don't match (+y -x):\n%s", diff)
		}

		dests, _, err := dp.Destinations()
		if err != nil {
			tb.Fatal(err)
		}

		if diff := cmp.Diff([]Destination{*dest}, dests); diff != "" {
			tb.Errorf("Destinations don't match (+y -x):\n%s", diff)
		}

		haveMetrics, err := dp.Metrics()
		if err != nil {
			tb.Fatal(err)
		}

		if diff := cmp.Diff(metrics, haveMetrics); diff != "" {
			tb.Errorf("Metrics don't match (+y -x):\n%s", diff)
		}

		testutil.CanDialName(tb, netns, "tcp", "127.0.0.1:443", "service")

		filesAfter := filesInDirectory(tb, dp.Path)
		if diff := cmp.Diff(filesBefore, filesAfter); diff != "" {
			tb.Fatal("Filesystem state before and after doesn't match:\n", diff)
		}
	}
}

func TestDispatcherUpgradeWithIncompatibleMap(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns)
	path := dp.Path
	dp.Close()

	hash, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    3,
		ValueSize:  99,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hash.Close()

	spec, err := loadPatchedDispatcher(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	for name := range spec.Maps {
		t.Log("Overriding", name)
		path := filepath.Join(path, name)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := hash.Pin(path); err != nil {
			t.Fatal(err)
		}

		// Only override one of the maps.
		break
	}

	if _, err := UpgradeDispatcher(netns.Path(), "/sys/fs/bpf"); err == nil {
		t.Fatal("Upgrading a dispatcher with an incompatible map doesn't return an error")
	}
}

func TestDispatcherAccess(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns)
	bind := mustNewBinding(t, "foo", TCP, "127.0.0.1", 8080)
	mustAddBinding(t, dp, bind)
	dp.Close()

	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal("Lookup nobody user:", err)
	}

	uid, err := strconv.Atoi(nobody.Uid)
	if err != nil {
		t.Fatal(err)
	}

	gid, err := strconv.Atoi(nobody.Gid)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("group read-write", func(t *testing.T) {
		err := testutil.WithCapabilities(func() (err error) {
			if err := cap.SetUID(uid); err != nil {
				return fmt.Errorf("set uid: %s", err)
			}

			dp, err := OpenDispatcher(netns.Path(), "/sys/fs/bpf", false)
			if err == nil {
				dp.Close()
			}
			return err
		})

		if err == nil {
			t.Fatal("Managed to open R/W dispatcher as group")
		}
	})

	t.Run("group read-only", func(t *testing.T) {
		var dp *Dispatcher
		err := testutil.WithCapabilities(func() (err error) {
			if err := cap.SetUID(uid); err != nil {
				return fmt.Errorf("set uid: %s", err)
			}

			dp, err = OpenDispatcher(netns.Path(), "/sys/fs/bpf", true)
			return
		})
		if err != nil {
			t.Fatal("Open dispatcher with shared group:", err)
		}
		defer dp.Close()

		if err := dp.AddBinding(bind); err == nil {
			t.Fatal("Group is able to add binding")
		}

		ln := testutil.Listen(t, netns, "tcp", "")
		if _, _, err := dp.RegisterSocket("foo", ln); err == nil {
			t.Fatal("Group is able to add socket")
		}
	})

	for _, readOnly := range []bool{true, false} {
		t.Run(fmt.Sprintf("others read-only=%t", readOnly), func(t *testing.T) {
			err := testutil.WithCapabilities(func() (err error) {
				if err := cap.SetUID(uid); err != nil {
					return fmt.Errorf("set uid: %s", err)
				}

				if err := cap.SetGroups(gid); err != nil {
					return fmt.Errorf("set gid: %s", err)
				}

				dp, err := OpenDispatcher(netns.Path(), "/sys/fs/bpf", readOnly)
				if err == nil {
					dp.Close()
				}
				return err
			})

			if err == nil {
				t.Fatal("Managed to open dispatcher")
			}
		})
	}
}

func TestAddAndRemoveBindings(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns)

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

func TestAddInvalidBinding(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns)

	testCases := []struct {
		ip string
		*Binding
	}{
		{"[::ffff:127.0.0.1]", mustNewBinding(t, "foo", TCP, "::ffff:127.0.0.1/128", 8080)},
		{"[::ffff:127.0.0.1]", mustNewBinding(t, "foo", TCP, "::ffff:127.0.0.1", 8080)},
		{"[::ffff:7f00:1]", mustNewBinding(t, "foo", TCP, "::ffff:7f00:1/104", 8080)},
	}

	for _, tc := range testCases {
		name := fmt.Sprintf("%v %s", tc.Protocol, tc.Prefix)
		t.Run(name, func(t *testing.T) {
			if err := dp.AddBinding(tc.Binding); err == nil {
				t.Fatal("Created/added an invalid binding:", tc.Binding.Prefix)
			}
		})
	}
}

func TestBindingWithEmptyLabel(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns)

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
			dp := mustCreateDispatcher(t, netns)

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
	dp := mustCreateDispatcher(t, netns)
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
		dp := mustCreateDispatcher(t, netns)

		if _, _, err := dp.ReplaceBindings(Bindings{a, aRelabeled}); err == nil {
			t.Error("ReplaceBindings doesn't reject multiple labels for the same binding")
		}
	})

	testcases := []struct {
		initial, replacement, added, removed Bindings
	}{
		{nil, nil, nil, nil},
		{nil, Bindings{a}, Bindings{a}, nil},
		{Bindings{a}, Bindings{a}, nil, nil},
		{nil, Bindings{a, b}, Bindings{a, b}, nil},
		{Bindings{a}, Bindings{b}, Bindings{b}, Bindings{a}},
		{Bindings{a}, Bindings{aRelabeled}, Bindings{aRelabeled}, nil},
		{Bindings{a, b}, nil, nil, Bindings{a, b}},
	}

	for _, test := range testcases {
		name := fmt.Sprintf("%v->%v", test.initial, test.replacement)
		t.Run(name, func(t *testing.T) {
			netns := testutil.NewNetNS(t)
			dp := mustCreateDispatcher(t, netns)

			for _, bind := range test.initial {
				if err := dp.AddBinding(bind); err != nil {
					t.Fatal(err)
				}
			}

			added, removed, err := dp.ReplaceBindings(test.replacement)
			if err != nil {
				t.Fatal("ReplaceBindings failed:", err)
			}

			sort.Sort(test.added)
			sort.Sort(added)
			if diff := cmp.Diff(test.added, added, testutil.IPPrefixComparer()); diff != "" {
				t.Errorf("added doesn't match (-want +got):\n%s", diff)
			}

			sort.Sort(test.removed)
			sort.Sort(removed)
			if diff := cmp.Diff(test.removed, removed, testutil.IPPrefixComparer()); diff != "" {
				t.Errorf("removed doesn't match (-want +got):\n%s", diff)
			}

			have, err := dp.Bindings()
			if err != nil {
				t.Fatal(err)
			}

			sort.Sort(test.replacement)
			sort.Sort(have)
			if diff := cmp.Diff(test.replacement, have, testutil.IPPrefixComparer()); diff != "" {
				t.Errorf("bindings don't match (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRegisterSupportedSocketKind(t *testing.T) {
	netns := testutil.NewNetNS(t)
	dp := mustCreateDispatcher(t, netns)

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
	dp := mustCreateDispatcher(t, netns)

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
	dp := mustCreateDispatcher(t, netns)

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
	dp := mustCreateDispatcher(t, netns)

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
	dp := mustCreateDispatcher(t, netns)
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
	dp := mustCreateDispatcher(t, netns)

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

func BenchmarkDispatcherAddBinding(b *testing.B) {
	netns := testutil.NewNetNS(b)
	dp := mustCreateDispatcher(b, netns)
	bindings := mustReadBindings(b, "some-label")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bind := bindings[rand.Intn(len(bindings))]
		mustAddBinding(b, dp, bind)
	}
	b.StopTimer()
}

func BenchmarkDispatcherManyBindings(b *testing.B) {
	const label = "some-label"

	var v4, v6 []netaddr.IP
	bindings := mustReadBindings(b, label)
	for _, bind := range bindings {
		if bind.Prefix.IP().Is4() {
			v4 = append(v4, bind.Prefix.IP())
		} else {
			v6 = append(v6, bind.Prefix.IP())
		}
	}
	b.Log(len(bindings), "bindings")

	if len(v4) == 0 {
		b.Fatal("No IPv4 addresses")
	}

	if len(v6) == 0 {
		b.Fatal("No IPv6 addresses")
	}

	var stats io.Closer
	err := testutil.WithCapabilities(func() (err error) {
		stats, err = ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
		return
	}, cap.SYS_ADMIN)
	if err != nil {
		b.Fatal("Enable stats:", err)
	}
	defer stats.Close()

	targets := []struct {
		name   string
		listen string
		addr   netaddr.IP
	}{
		{"IPv4", "127.0.0.1:0", v4[rand.Intn(len(v4))]},
		{"IPv6", "[::1]:0", v6[rand.Intn(len(v6))]},
	}

	buf := []byte("foobar")

	networks := []string{
		"249.0.0.0/8",
		"250.0.0.0/8",
		"251.0.0.0/8",
		"252.0.0.0/8",
		"253.0.0.0/8",
		"254.0.0.0/8",
		"255.0.0.0/8",
		"2001:db8::/32",
	}

	for _, target := range targets {
		b.Log("Chosen target", target.addr)

		b.Run(target.name, func(b *testing.B) {
			netns := testutil.NewNetNS(b, networks...)
			dp := mustCreateDispatcher(b, netns)

			// We need a socket registered, otherwise the kernel will send
			// ICMP destination unreachable.
			ln := testutil.ListenAndEcho(b, netns, "udp", target.listen)
			testutil.DropIncomingTraffic(b, ln)
			mustRegisterSocket(b, dp, label, ln)

			for _, bind := range bindings {
				mustAddBinding(b, dp, bind)
			}

			var src *net.UDPConn
			testutil.JoinNetNS(b, netns, func() (err error) {
				laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
				if target.addr.Is6() {
					laddr.IP = net.IPv6loopback
				}
				src, err = net.ListenUDP("udp", laddr)
				return
			})
			defer src.Close()

			b.ResetTimer()
			addr := &net.UDPAddr{IP: target.addr.IPAddr().IP, Port: 53}
			for i := 0; i < b.N; i++ {
				if _, err := src.WriteToUDP(buf, addr); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()

			prog, err := dp.Program()
			if err != nil {
				b.Fatal("Get program:", err)
			}
			defer prog.Close()

			info, err := prog.Info()
			if err != nil {
				b.Fatal("Get program info:", err)
			}

			n, _ := info.RunCount()
			if n != uint64(b.N) {
				// sk_lookup runs when we send a packet, and when we get a response.
				b.Fatalf("Expected %d iterations, got %d", b.N, n)
			}

			duration, _ := info.Runtime()
			b.ReportMetric(float64(duration.Nanoseconds())/float64(n), "ns/op")
		})
	}
}

func TestMain(m *testing.M) {
	contents, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled")
	if err != nil {
		panic(err)
	}

	if value := strings.TrimSpace(string(contents)); value != "0" {
		fmt.Fprintln(os.Stderr, "Tests require kernel.unprivileged_bpf_disabled=0")
		os.Exit(1)
	}

	os.Exit(m.Run())
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

func mustRegisterSocket(tb testing.TB, dp *Dispatcher, label string, conn syscall.Conn) *Destination {
	tb.Helper()

	dest, _, err := dp.RegisterSocket(label, conn)
	if err != nil {
		tb.Fatal("Register socket:", err)
	}

	return dest
}

func mustCreateDispatcher(tb testing.TB, netns ns.NetNS) *Dispatcher {
	tb.Helper()

	var dp *Dispatcher
	err := testutil.WithCapabilities(func() (err error) {
		dp, err = CreateDispatcher(netns.Path(), "/sys/fs/bpf")
		return
	}, CreateCapabilities...)
	if err != nil {
		tb.Fatal("Can't create dispatcher:", err)
	}

	dir, err := os.Open(dp.Path)
	if err != nil {
		tb.Fatal("Can't open state directory:", err)
	}
	defer dir.Close()

	if lock.Exclusive(dir).TryLock() {
		tb.Fatal("State directory isn't locked after creation")
	}

	tb.Cleanup(func() {
		dir, err := os.Open(dp.Path)
		locked := false
		if err == nil {
			defer dir.Close()
			locked = !lock.Exclusive(dir).TryLock()
		}

		os.RemoveAll(dp.Path)
		if err := dp.Close(); err == nil {
			// Only check locking if the dispatcher wasn't closed before.
			if dir != nil && !locked {
				tb.Error("State directory isn't locked at end of execution")
			}
		}
	})
	return dp
}

func mustOpenDispatcher(tb testing.TB, logger log.Logger, netns ns.NetNS) *Dispatcher {
	tb.Helper()

	if logger == nil {
		logger = log.Discard
	}

	dp, err := OpenDispatcher(netns.Path(), "/sys/fs/bpf", false)
	if err != nil {
		tb.Fatal("Can't open dispatcher:", err)
	}

	return dp
}

func mustReadBindings(tb testing.TB, label string) []*Binding {
	file, err := os.Open("testdata/prefixes.json")
	if err != nil {
		tb.Fatal(err)
	}
	defer file.Close()

	var prefixes []string
	dec := json.NewDecoder(file)
	if err := dec.Decode(&prefixes); err != nil {
		tb.Fatal("Read prefixes:", err)
	}

	if len(prefixes) == 0 {
		tb.Fatal("prefixes.json contains no prefixes")
	}

	var bindings []*Binding
	for _, prefixStr := range prefixes {
		prefix, err := netaddr.ParseIPPrefix(prefixStr)
		if err != nil {
			tb.Fatal(err)
		}

		r := prefix.Range()
		for ip := r.From(); ip.Compare(r.To()) <= 0; ip = ip.Next() {
			bind := mustNewBinding(tb, label, UDP, ip.String(), 53)
			bindings = append(bindings, bind)
		}
	}

	return bindings
}
