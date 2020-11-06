package internal

import (
	"io/ioutil"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

func TestDestinationsHasID(t *testing.T) {
	dests := mustNewDestinations(t)
	foo := &Destination{"foo", AF_INET, TCP, 0}

	if dests.HasID(foo, 0) {
		t.Fatal("HasID returns true for non-existing destination")
	}

	id, err := dests.AcquireID(foo)
	if err != nil {
		t.Fatal("Can't allocate ID:", err)
	}
	if id != 0 {
		t.Fatal("Expected ID for foo to be 0, got", id)
	}

	if !dests.HasID(foo, id) {
		t.Error("Expected id for foo to match", id)
	}
}

func TestDestinationIDAllocation(t *testing.T) {
	acquire := func(t *testing.T, dests *destinations, dest *Destination, expectedID destinationID) {
		t.Helper()

		id, err := dests.AcquireID(dest)
		if err != nil {
			t.Fatal(err)
		}
		if id != expectedID {
			t.Fatalf("Expected ID for dest %s to be %d, got %d", dest, expectedID, id)
		}
	}

	release := func(t *testing.T, dests *destinations, dest *Destination) {
		t.Helper()

		if err := dests.ReleaseID(dest); err != nil {
			t.Fatal(err)
		}
	}

	var (
		foo   = &Destination{"foo", AF_INET, TCP, 0}
		bar   = &Destination{"bar", AF_INET, TCP, 0}
		baz   = &Destination{"baz", AF_INET, UDP, 0}
		bingo = &Destination{"bingo", AF_INET, UDP, 0}
		quux  = &Destination{"quux", AF_INET, UDP, 0}
		frood = &Destination{"frood", AF_INET, UDP, 0}
	)

	t.Run("release non-existing", func(t *testing.T) {
		lbls := mustNewDestinations(t)
		if err := lbls.ReleaseID(foo); err == nil {
			t.Error("Release doesn't return an error for non-existing labels")
		}
	})

	t.Run("sequential allocation", func(t *testing.T) {
		lbls := mustNewDestinations(t)
		acquire(t, lbls, foo, 0)
		acquire(t, lbls, bar, 1)
		acquire(t, lbls, baz, 2)
		checkDestinations(t, lbls, foo, bar, baz)
	})

	t.Run("usage counting", func(t *testing.T) {
		lbls := mustNewDestinations(t)
		acquire(t, lbls, foo, 0)
		acquire(t, lbls, foo, 0)
		release(t, lbls, foo)
		checkDestinations(t, lbls, foo)
		acquire(t, lbls, foo, 0)
		release(t, lbls, foo)
		checkDestinations(t, lbls, foo)
		release(t, lbls, foo)
		checkDestinations(t, lbls)
	})

	t.Run("allocate unused ids", func(t *testing.T) {
		lbls := mustNewDestinations(t)
		acquire(t, lbls, foo, 0)
		acquire(t, lbls, bar, 1)
		acquire(t, lbls, baz, 2)
		checkDestinations(t, lbls, foo, bar, baz)
		release(t, lbls, foo)
		checkDestinations(t, lbls, bar, baz)
		release(t, lbls, bar)
		checkDestinations(t, lbls, baz)
		acquire(t, lbls, bingo, 0)
		acquire(t, lbls, quux, 1)
		acquire(t, lbls, frood, 3)
		checkDestinations(t, lbls, baz, bingo, quux, frood)
	})
}

func TestDestinationsAddSocket(t *testing.T) {
	dests := mustNewDestinations(t)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	conn := mustRawConn(t, ln.(syscall.Conn))
	dest, err := newDestinationFromConn("foo", conn)
	if err != nil {
		t.Fatal(err)
	}

	if created, err := dests.AddSocket(dest, conn); err != nil {
		t.Fatal("Can't add socket:", err)
	} else if !created {
		t.Error("Adding a socket for the first time doesn't set created to true")
	}

	checkDestinations(t, dests, dest)

	if created, err := dests.AddSocket(dest, conn); err != nil {
		t.Fatal("Can't add socket:", err)
	} else if created {
		t.Error("Adding a socket for the second time sets created to true")
	}

	// TODO: Remove socket
}

func mustNewDestinations(tb testing.TB) *destinations {
	tb.Helper()

	tempDir, err := ioutil.TempDir("/sys/fs/bpf", "tubular")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { os.RemoveAll(tempDir) })

	spec, err := newDispatcherSpecs()
	if err != nil {
		tb.Fatal("Can't create specs:", err)
	}

	obj, err := spec.Load(&ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: tempDir},
	})
	if err != nil {
		tb.Fatal("Can't load objects:", err)
	}
	tb.Cleanup(func() { obj.Close() })

	lbls, err := newDestinations(obj, "")
	if err != nil {
		tb.Fatal("Can't create labels:", err)
	}
	tb.Cleanup(func() { lbls.Close() })
	return lbls
}

func mustRawConn(tb testing.TB, conn syscall.Conn) syscall.RawConn {
	tb.Helper()

	raw, err := conn.SyscallConn()
	if err != nil {
		tb.Fatal(err)
	}

	return raw
}

func checkDestinations(tb testing.TB, dests *destinations, want ...*Destination) {
	tb.Helper()

	set := make(map[Destination]bool)
	for _, dest := range want {
		set[*dest] = true
	}

	have, err := dests.List()
	if err != nil {
		tb.Fatal("Can't get destinations:", err)
	}

	for _, dest := range have {
		if set[*dest] {
			delete(set, *dest)
		} else {
			tb.Error("Extraneous destination:", dest)
		}
	}

	for dest := range set {
		tb.Error("Missing destination:", &dest)
	}
}
