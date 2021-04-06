package main

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"code.cfops.it/sys/tubular/internal/testutil"
)

const (
	dialDeadline = 5 * time.Second
	dialInterval = 5 * time.Millisecond

	maxResponseBytes = 128
)

func TestServeBadArgs(t *testing.T) {
	netns := testutil.NewNetNS(t)

	for _, tc := range []struct {
		name    string
		cmdArgs []string
		wantErr error
	}{
		{"listen address missing", []string{}, errBadArg},
		{"listen address empty", []string{""}, errBadArg},
		{"dynamic address empty", []string{"@"}, errBadArg},
		{"too many args", []string{"foo", "bar"}, errBadArg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tubectl := tubectlTestCall{
				NetNS: netns,
				Cmd:   "serve",
				Args:  tc.cmdArgs,
			}
			_, err := tubectl.Run(t)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("unexpected error: want %v, have %v", tc.wantErr, err)
			}
		})
	}
}

func TestServeAddressTypes(t *testing.T) {
	netns := testutil.NewNetNS(t)

	for _, tc := range []struct {
		name string
		addr string
	}{
		{"serve on pathname address", makeUnixPathnameAddr()},
		{"serve on abstract address", makeUnixAbstractAddr()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tubectl := tubectlTestCall{
				NetNS: netns,
				Cmd:   "serve",
				Args:  []string{tc.addr},
			}
			stop := tubectl.Start(t)

			conn, err := dialUnixpacketTimeoutAndRetry(tc.addr)
			if err != nil {
				t.Fatalf("can't dial server at %v: %v", tc.addr, err)
			}
			conn.Close()

			stop()

			// Check if pathname socket gets cleaned up on exit
			if _, err := os.Stat(tc.addr); !os.IsNotExist(err) {
				t.Fatalf("socket file present at %v", tc.addr)
			}
		})
	}
}

func TestServeMany(t *testing.T) {
	netns := testutil.NewNetNS(t)

	for _, tc := range []struct {
		name     string
		addr     string
		numIters int
		numConns int
	}{
		{"serve 10 clients in series", makeUnixAbstractAddr(), 10, 1},
		{"serve 10 clients in parallel", makeUnixAbstractAddr(), 1, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tubectl := tubectlTestCall{
				NetNS: netns,
				Cmd:   "serve",
				Args:  []string{tc.addr},
			}
			tubectl.Start(t)

			conns := make([]*net.UnixConn, tc.numConns)
			t.Cleanup(func() {
				for _, c := range conns {
					if c != nil {
						c.Close()
					}
				}
			})

			for i := 0; i < tc.numIters; i++ {
				for j := range conns {
					c, err := dialUnixpacketTimeoutAndRetry(tc.addr)
					if err != nil {
						t.Fatalf("can't dial server at %v: %v", tc.addr, err)
						break
					}
					conns[j] = c

					_, err = c.Write([]byte("version"))
					if err != nil {
						t.Fatalf("can't send request: %v", err)
						break
					}

					resp := make([]byte, maxResponseBytes)
					n, err := c.Read(resp)
					if err != nil {
						t.Fatalf("can't receive response: %v", err)
					}

					resp = resp[:n]
					if !bytes.Equal(resp, []byte(Version)) {
						t.Fatalf("unexpected server response: want %q, have %q", Version, string(resp))
					}
				}

				for j, c := range conns {
					c.Close()
					conns[j] = nil
				}
			}
		})
	}
}

func dialUnixpacketTimeoutAndRetry(addr string) (*net.UnixConn, error) {
	ua := resolveUnixAddr("unixpacket", addr)
	delay := dialInterval
	var duration time.Duration
	for {
		if c, err := net.DialTimeout(ua.Network(), ua.String(), dialDeadline); err == nil {
			return c.(*net.UnixConn), nil
		} else {
			if os.IsTimeout(err) {
				return nil, err
			}
			if duration >= dialDeadline {
				return nil, fmt.Errorf("dial timeout: %w", err)
			}
			time.Sleep(delay)
			duration += delay
			delay *= 2
		}
	}
}

var rng = rand.New(rand.NewSource(time.Now().UnixNano() + int64(os.Getpid())))

func makeUnixPathnameAddr() string {
	return path.Join(os.TempDir(), fmt.Sprintf("tubectl_serve_test-%08x.sock", rng.Uint64()))
}

func makeUnixAbstractAddr() string {
	return fmt.Sprintf("@tubectl_serve_test-%08x", rng.Uint64())
}
