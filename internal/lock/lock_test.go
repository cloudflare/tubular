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
		a, b        func(*os.File) (*File, error)
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
			a, err := test.a(newHandle())
			if err != nil {
				t.Fatal("Can't create lock a:", err)
			}

			b, err := test.b(newHandle())
			if err != nil {
				t.Fatal("Can't create lock:", err)
			}

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
