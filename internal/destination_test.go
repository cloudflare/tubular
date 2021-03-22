package internal

import (
	"net"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

func TestDestinationsHasID(t *testing.T) {
	dests := mustNewDestinations(t)
	foo := &Destination{"foo", AF_INET, TCP}

	if dests.HasID(foo, 0) {
		t.Fatal("HasID returns true for non-existing destination")
	}

	id, err := dests.Acquire(foo)
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

		id, err := dests.Acquire(dest)
		if err != nil {
			t.Fatal(err)
		}
		if id != expectedID {
			t.Fatalf("Expected ID for dest %s to be %d, got %d", dest, expectedID, id)
		}
	}

	release := func(t *testing.T, dests *destinations, dest *Destination) {
		t.Helper()

		if err := dests.Release(dest); err != nil {
			t.Fatal(err)
		}
	}

	var (
		foo   = &Destination{"foo", AF_INET, TCP}
		bar   = &Destination{"bar", AF_INET, TCP}
		baz   = &Destination{"baz", AF_INET, UDP}
		bingo = &Destination{"bingo", AF_INET, UDP}
		quux  = &Destination{"quux", AF_INET, UDP}
		frood = &Destination{"frood", AF_INET, UDP}
	)

	t.Run("release non-existing", func(t *testing.T) {
		dests := mustNewDestinations(t)
		if err := dests.Release(foo); err == nil {
			t.Error("Release doesn't return an error for non-existing labels")
		}
	})

	t.Run("sequential allocation", func(t *testing.T) {
		dests := mustNewDestinations(t)
		acquire(t, dests, foo, 0)
		acquire(t, dests, bar, 1)
		acquire(t, dests, baz, 2)
		checkDestinations(t, dests, foo, bar, baz)
	})

	t.Run("usage counting", func(t *testing.T) {
		dests := mustNewDestinations(t)
		acquire(t, dests, foo, 0)
		acquire(t, dests, foo, 0)
		release(t, dests, foo)
		checkDestinations(t, dests, foo)
		acquire(t, dests, foo, 0)
		release(t, dests, foo)
		checkDestinations(t, dests, foo)
		release(t, dests, foo)
		checkDestinations(t, dests)
	})

	t.Run("allocate unused ids", func(t *testing.T) {
		dests := mustNewDestinations(t)
		acquire(t, dests, foo, 0)
		acquire(t, dests, bar, 1)
		acquire(t, dests, baz, 2)
		checkDestinations(t, dests, foo, bar, baz)
		release(t, dests, foo)
		checkDestinations(t, dests, bar, baz)
		release(t, dests, bar)
		checkDestinations(t, dests, baz)
		acquire(t, dests, bingo, 0)
		acquire(t, dests, quux, 1)
		acquire(t, dests, frood, 3)
		checkDestinations(t, dests, baz, bingo, quux, frood)
	})

	t.Run("release by id", func(t *testing.T) {
		dests := mustNewDestinations(t)
		acquire(t, dests, foo, 0)

		if dests.ReleaseByID(1) == nil {
			t.Error("ReleaseByID accepts an unallocated ID")
		}

		if err := dests.ReleaseByID(0); err != nil {
			t.Fatal("ReleaseByID doesn't release valid ID:", err)
		}

		checkDestinations(t, dests)
	})
}

func TestDestinationsAddSocket(t *testing.T) {
	dests := mustNewDestinations(t)

	sockets, err := dests.Sockets()
	if err != nil {
		t.Fatal("Can't get sockets:", err)
	}
	if len(sockets) != 0 {
		t.Fatal("Expected no sockets, got", len(sockets))
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	conn := ln.(syscall.Conn)
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

	sockets, err = dests.Sockets()
	if err != nil {
		t.Fatal("Can't get sockets:", err)
	}
	if len(sockets) != 1 {
		t.Fatal("Expected one sockets, got", len(sockets))
	}

	// TODO: Remove socket
}

func mustNewDestinations(tb testing.TB) *destinations {
	tb.Helper()

	spec, err := loadPatchedDispatcher(nil, nil)
	if err != nil {
		tb.Fatal(err)
	}

	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}

	var maps dispatcherMaps
	if err := spec.LoadAndAssign(&maps, nil); err != nil {
		tb.Fatal("Can't create specs:", err)
	}
	tb.Cleanup(func() { maps.Close() })

	dests := newDestinations(maps)
	tb.Cleanup(func() { dests.Close() })
	return dests
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
