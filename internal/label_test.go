package internal

import "testing"

func TestLabels(t *testing.T) {
	lbls := mustNewLabels(t)

	if id, err := lbls.FindID("foo"); err != nil {
		t.Fatal("Can't look up non-existing ID")
	} else if id != 0 {
		t.Error("FindID doesn't return 0 for non-existing ID")
	}

	id, err := lbls.AllocateID("foo")
	if err != nil {
		t.Fatal("Can't allocate ID:", err)
	}
	if id != 1 {
		t.Errorf("Expected first ID to be 1, got %d", id)
	}

	idBar, err := lbls.AllocateID("bar")
	if err != nil {
		t.Fatal("Can't allocate ID:", err)
	}
	if idBar != 2 {
		t.Errorf("Expected first ID to be 2, got %d", idBar)
	}

	foundID, err := lbls.FindID("foo")
	if err != nil {
		t.Fatal(err)
	}
	if id != foundID {
		t.Fatalf("Expected ids for existing label to match, got %d and %d", id, foundID)
	}

	labels, err := lbls.List()
	if err != nil {
		t.Fatal("List returns an error:", err)
	}

	if n := len(labels); n != 2 {
		t.Error("Expected two labels, got", n)
	}
	if labels[id] != "foo" {
		t.Errorf("Expected id 1 to have label foo, got %q", labels[id])
	}
	if labels[idBar] != "bar" {
		t.Errorf("Expected id 2 to have label bar, got %q", labels[idBar])
	}

	if err := lbls.Delete("foo"); err != nil {
		t.Fatal("Can't delete label:", err)
	}

	foundID, err = lbls.FindID("foo")
	if err != nil {
		t.Fatal(err)
	}
	if foundID != 0 {
		t.Fatal("Delete doesn't remove labels")
	}
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
