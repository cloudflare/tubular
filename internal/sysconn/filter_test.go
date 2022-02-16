package sysconn_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"syscall"
	"testing"

	"code.cfops.it/sys/tubular/internal/sysconn"
	"code.cfops.it/sys/tubular/internal/testutil"

	"github.com/google/go-cmp/cmp"
	"inet.af/netaddr"
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
			if keep, err := sysconn.FilterConn(conns[0], p); err != nil {
				t.Fatalf("%s group %d socket 1: %s", network, group, err)
			} else if !keep {
				t.Fatalf("Predicate wouldn't keep first %s socket of group %d", network, group)
			}

			for i, conn := range conns[1:] {
				if keep, err := sysconn.FilterConn(conn, p); err != nil {
					t.Fatalf("%s group %d socket %d: %s", network, group, i+1, err)
				} else if keep {
					t.Fatalf("Predicate would keep %s socket #%d of group %d", network, i+1, group)
				}
			}
		}
	}
}

func TestLocalAddress(t *testing.T) {
	type test struct {
		name string
		p    sysconn.Predicate
		conn syscall.Conn
		keep bool
	}

	var valid []test
	addValid := func(network string, conn syscall.Conn, ip netaddr.IP, port int) {
		valid = append(valid,
			test{
				fmt.Sprint(network, " ip and port"),
				sysconn.LocalAddress(ip, port),
				conn,
				true,
			},
			test{
				fmt.Sprint(network, " drop ip"),
				sysconn.LocalAddress(ip.Next(), port),
				conn,
				false,
			},
			test{
				fmt.Sprint(network, " drop port"),
				sysconn.LocalAddress(ip, port+1),
				conn,
				false,
			},
		)
	}

	for _, addr := range []string{"127.0.0.1:0", "[::1]:0"} {
		tcp, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer tcp.Close()

		addr := tcp.Addr().(*net.TCPAddr)
		ip, _ := netaddr.FromStdIP(addr.IP)
		addValid("tcp", tcp.(syscall.Conn), ip, addr.Port)
	}

	for _, addr := range []string{"127.0.0.1:0", "[::1]:0"} {
		udp, err := net.Dial("udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer udp.Close()

		addr := udp.LocalAddr().(*net.UDPAddr)
		ip, _ := netaddr.FromStdIP(addr.IP)
		addValid("udp", udp.(syscall.Conn), ip, addr.Port)
	}

	unixConn, err := net.ListenUnix("unix", &net.UnixAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer unixConn.Close()

	valid = append(valid, test{
		"unix",
		sysconn.LocalAddress(netaddr.IP{}, 0),
		unixConn,
		false,
	})

	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			keep, err := sysconn.FilterConn(test.conn, test.p)
			if err != nil {
				t.Fatal("Predicate returned an error:", err)
			}
			if keep != test.keep {
				t.Fatalf("Predicate didn't match, want %t got %t", test.keep, keep)
			}
		})
	}

	file, err := ioutil.TempFile("", "tubular")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	invalid := []test{
		{
			"file",
			sysconn.LocalAddress(netaddr.IP{}, 0),
			file,
			false,
		},
	}

	for _, test := range invalid {
		t.Run("invalid "+test.name, func(t *testing.T) {
			keep, err := sysconn.FilterConn(test.conn, test.p)
			if err == nil {
				t.Fatal("Predicate did not return an error")
			}
			if keep {
				t.Fatal("Predicate returned a match and an error")
			}
		})
	}
}

func TestListeningSocket(t *testing.T) {
	file, err := ioutil.TempFile("", "tubular")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	unixConn, err := net.ListenUnix("unix", &net.UnixAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer unixConn.Close()

	udpConn := testutil.Listen(t, testutil.CurrentNetNS(t), "udp", "")
	tcpConn := testutil.Listen(t, testutil.CurrentNetNS(t), "tcp", "")

	_, err = sysconn.FilterConn(udpConn, sysconn.InetListener(""))
	if err == nil {
		t.Error("Empty protocol should return an error")
	}

	_, err = sysconn.FilterConn(tcpConn, sysconn.InetListener("garbage"))
	if err == nil {
		t.Error("Garbage protocol should return an error")
	}

	type test struct {
		name string
		p    sysconn.Predicate
		conn syscall.Conn
		keep bool
	}

	var tests = []test{
		{
			"udp",
			sysconn.InetListener("udp"),
			udpConn,
			true,
		},
		{
			"udp wrong proto",
			sysconn.InetListener("tcp"),
			udpConn,
			false,
		},
		{
			"tcp",
			sysconn.InetListener("tcp"),
			tcpConn,
			true,
		},
		{
			"tcp wrong proto",
			sysconn.InetListener("udp"),
			tcpConn,
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keep, err := sysconn.FilterConn(test.conn, test.p)
			if err != nil {
				t.Fatal("Predicate returned an error:", err)
			}
			if keep != test.keep {
				t.Fatalf("Predicate didn't match, want %t got %t", test.keep, keep)
			}
		})
	}
}
