package sysconn_test

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"code.cfops.it/sys/tubular/internal/sysconn"
	"code.cfops.it/sys/tubular/internal/testutil"
	"github.com/google/go-cmp/cmp"
)

func TestFilter(t *testing.T) {
	conns := testutil.ReuseportGroup(t, testutil.CurrentNetNS(t), "udp4", 4)

	var keep bool
	tests := []struct {
		name   string
		p      sysconn.Predicate
		result []syscall.Conn
	}{
		{"all", func(_ int) (bool, error) { return true, nil }, conns},
		{"none", func(_ int) (bool, error) { return false, nil }, nil},
		{"even", func(_ int) (bool, error) {
			keep = !keep
			return keep, nil
		}, []syscall.Conn{
			conns[0],
			conns[2],
		}},
	}

	comparer := cmp.Comparer(func(x, y *net.UDPConn) bool {
		return x == y
	})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := sysconn.Filter(conns, test.p)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(test.result, got, comparer); diff != "" {
				t.Errorf("conns don't match (+y -x):\n%s", diff)
			}
		})
	}
}

func TestFilterError(t *testing.T) {
	conns := testutil.ReuseportGroup(t, testutil.CurrentNetNS(t), "udp4", 1)
	result, err := sysconn.Filter(conns, func(_ int) (bool, error) {
		return false, errors.New("bogus")
	})
	if err == nil {
		t.Fatal("Filter doesn't return error")
	}
	if result != nil {
		t.Fatal("Filter returns a result alongside an error")
	}
}

func TestFirstReuseport(t *testing.T) {
	p := sysconn.FirstReuseport()

	netns := testutil.CurrentNetNS(t)

	for _, network := range []string{
		"udp4",
		"udp6",
		"tcp4",
		"tcp6",
	} {
		for group := 0; group < 2; group++ {
			conns := testutil.ReuseportGroup(t, netns, network, 2)
			if keep, err := p.Apply(conns[0]); err != nil {
				t.Fatalf("%s group %d socket 1: %s", network, group, err)
			} else if !keep {
				t.Fatalf("Predicate wouldn't keep first %s socket of group %d", network, group)
			}

			for i, conn := range conns[1:] {
				if keep, err := p.Apply(conn); err != nil {
					t.Fatalf("%s group %d socket %d: %s", network, group, i+1, err)
				} else if keep {
					t.Fatalf("Predicate would keep %s socket #%d of group %d", network, i+1, group)
				}
			}
		}
	}
}
