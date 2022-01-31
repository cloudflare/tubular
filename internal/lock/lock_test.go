package lock

import (
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestLocking(t *testing.T) {
	tests := []struct {
		name        string
		a, b        func(*os.File) *File
		shouldBlock bool
	}{
		{"Ex-Ex", Exclusive, Exclusive, true},
		{"Ex-Sh", Exclusive, Shared, true},
		{"Sh-Sh", Shared, Shared, false},
		{"Sh-Ex", Shared, Exclusive, true},
	}

	chanClosed := func(ch <-chan struct{}) bool {
		select {
		case <-ch:
			return true
		case <-time.After(50 * time.Millisecond):
			return false
		}
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			newHandle := mustTempDir(t)
			a := test.a(newHandle())
			b := test.b(newHandle())

			a.Lock()
			acquired := make(chan struct{})
			go func() {
				b.Lock()
				close(acquired)
			}()
			defer b.Unlock()

			if test.shouldBlock {
				if chanClosed(acquired) {
					t.Fatal("Lock doesn't block")
				}

				a.Unlock()

				if !chanClosed(acquired) {
					t.Fatal("Unlock doesn't unblock")
				}
			} else {
				if !chanClosed(acquired) {
					t.Fatal("Lock blocks")
				}

				a.Unlock()
			}
		})
	}
}

func TestTryLock(t *testing.T) {
	newHandle := mustTempDir(t)
	a := Exclusive(newHandle())
	defer a.Close()

	b := Exclusive(newHandle())
	defer b.Close()

	a.Lock()
	if b.TryLock() {
		t.Fatal("TryLock shouldn't succeed")
	}

	a.Unlock()
	if !b.TryLock() {
		t.Fatal("TryLock should succeed")
	}
}

func mustTempDir(tb testing.TB) func() *os.File {
	tb.Helper()

	dir, err := ioutil.TempDir("", "tubular")
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		os.RemoveAll(dir)
	})

	return func() *os.File {
		handle, err := os.Open(dir)
		if err != nil {
			tb.Fatal("Can't open temporary dir:", err)
		}
		tb.Cleanup(func() { handle.Close() })
		return handle
	}
}
