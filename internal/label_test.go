package internal

import "testing"

func TestLabelID(t *testing.T) {
	lbls := mustNewLabels(t)

	if _, err := lbls.ID("foo"); err == nil {
		t.Fatal("No error when looking up non-existing label")
	}

	id, err := lbls.allocateID("foo")
	if err != nil {
		t.Fatal("Can't allocate ID:", err)
	}
	if id != 1 {
		t.Fatal("Expected ID for foo to be 1, got", id)
	}

	foundID, err := lbls.ID("foo")
	if err != nil {
		t.Fatal("Can't lookup foo:", err)
	}

	if foundID != id {
		t.Errorf("Expected id %d for label foo, got %d", id, foundID)
	}
}

func TestLabelIDAllocation(t *testing.T) {
	acquire := func(t *testing.T, lbls *labels, label string, expectedID labelID) {
		t.Helper()

		id, err := lbls.Acquire(label)
		if err != nil {
			t.Fatal(err)
		}
		if id != expectedID {
			t.Fatalf("Expected ID for label %q to be %d, got %d", label, expectedID, id)
		}
	}

	release := func(t *testing.T, lbls *labels, label string) {
		t.Helper()

		if err := lbls.Release(label); err != nil {
			t.Fatal(err)
		}
	}

	check := func(t *testing.T, lbls *labels, want ...string) {
		t.Helper()

		set := make(map[string]bool)
		for _, label := range want {
			set[label] = true
		}

		labels, err := lbls.List()
		if err != nil {
			t.Fatal("Can't get labels:", err)
		}

		for _, label := range labels {
			if set[label] {
				delete(set, label)
			} else {
				t.Error("Extraneous label:", label)
			}
		}

		for label := range set {
			t.Error("Missing label:", label)
		}
	}

	t.Run("release non-existing", func(t *testing.T) {
		lbls := mustNewLabels(t)
		if err := lbls.Release("foobar"); err == nil {
			t.Error("Release doesn't return an error for non-existing labels")
		}
	})

	t.Run("sequential allocation", func(t *testing.T) {
		lbls := mustNewLabels(t)
		acquire(t, lbls, "foo", 1)
		acquire(t, lbls, "bar", 2)
		acquire(t, lbls, "baz", 3)
		check(t, lbls, "foo", "bar", "baz")
	})

	t.Run("usage counting", func(t *testing.T) {
		lbls := mustNewLabels(t)
		acquire(t, lbls, "foo", 1)
		acquire(t, lbls, "foo", 1)
		release(t, lbls, "foo")
		check(t, lbls, "foo")
		acquire(t, lbls, "foo", 1)
		release(t, lbls, "foo")
		check(t, lbls, "foo")
		release(t, lbls, "foo")
		check(t, lbls)
	})

	t.Run("allocate unused ids", func(t *testing.T) {
		lbls := mustNewLabels(t)
		acquire(t, lbls, "foo", 1)
		acquire(t, lbls, "bar", 2)
		acquire(t, lbls, "baz", 3)
		check(t, lbls, "foo", "bar", "baz")
		release(t, lbls, "foo")
		check(t, lbls, "bar", "baz")
		release(t, lbls, "bar")
		check(t, lbls, "baz")
		acquire(t, lbls, "bingo", 1)
		acquire(t, lbls, "quux", 2)
		acquire(t, lbls, "frood", 4)
		check(t, lbls, "baz", "bingo", "quux", "frood")
	})
}

func mustNewLabels(tb testing.TB) *labels {
	lbls, err := newLabels()
	if err != nil {
		tb.Helper()
		tb.Fatal("Can't create labels:", err)
	}
	tb.Cleanup(func() { lbls.Close() })
	return lbls
}
