package internal

import (
	"testing"
)

func TestDestinationID(t *testing.T) {
	dests := mustNewDestinations(t)
	foo := &Destination{"foo", AF_INET, TCP, 0}

	if dests.HasID(foo, 0) {
		t.Fatal("HasID returns true for non-existing destination")
	}

	id, err := dests.AcquireID(foo)
	if err != nil {
		t.Fatal("Can't allocate ID:", err)
	}
	if id != 1 {
		t.Fatal("Expected ID for foo to be 1, got", id)
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

	check := func(t *testing.T, dests *destinations, want ...*Destination) {
		t.Helper()

		set := make(map[Destination]bool)
		for _, dest := range want {
			set[*dest] = true
		}

		have, err := dests.List()
		if err != nil {
			t.Fatal("Can't get destinations:", err)
		}

		for _, dest := range have {
			if set[*dest] {
				delete(set, *dest)
			} else {
				t.Error("Extraneous destination:", dest)
			}
		}

		for dest := range set {
			t.Error("Missing destination:", &dest)
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
		acquire(t, lbls, foo, 1)
		acquire(t, lbls, bar, 2)
		acquire(t, lbls, baz, 3)
		check(t, lbls, foo, bar, baz)
	})

	t.Run("usage counting", func(t *testing.T) {
		lbls := mustNewDestinations(t)
		acquire(t, lbls, foo, 1)
		acquire(t, lbls, foo, 1)
		release(t, lbls, foo)
		check(t, lbls, foo)
		acquire(t, lbls, foo, 1)
		release(t, lbls, foo)
		check(t, lbls, foo)
		release(t, lbls, foo)
		check(t, lbls)
	})

	t.Run("allocate unused ids", func(t *testing.T) {
		lbls := mustNewDestinations(t)
		acquire(t, lbls, foo, 1)
		acquire(t, lbls, bar, 2)
		acquire(t, lbls, baz, 3)
		check(t, lbls, foo, bar, baz)
		release(t, lbls, foo)
		check(t, lbls, bar, baz)
		release(t, lbls, bar)
		check(t, lbls, baz)
		acquire(t, lbls, bingo, 1)
		acquire(t, lbls, quux, 2)
		acquire(t, lbls, frood, 4)
		check(t, lbls, baz, bingo, quux, frood)
	})
}

func mustNewDestinations(tb testing.TB) *destinations {
	tb.Helper()

	spec, err := newDispatcherSpecs()
	if err != nil {
		tb.Fatal("Can't create specs:", err)
	}

	obj, err := spec.Load(nil)
	if err != nil {
		tb.Fatal("Can't load objects:", err)
	}
	tb.Cleanup(func() { obj.Close() })

	lbls, err := newDestinations(obj)
	if err != nil {
		tb.Fatal("Can't create labels:", err)
	}
	tb.Cleanup(func() { lbls.Close() })
	return lbls
}
