package main

import (
	"syscall"
	"testing"

	"code.cfops.it/sys/tubular/internal/testutil"
)

func TestUnregister(t *testing.T) {
	// Generate a new netns/dispatcher for the test
	netns := mustReadyNetNS(t)

	// Make the listening socket that matches what we remove, and one that doesn't
	fds := testFds{makeListeningSocket(t, netns, "tcp4"), makeListeningSocket(t, netns, "tcp6")}

	flags := make(map[syscall.Conn]int)
	for _, f := range fds {
		if f != nil {
			flags[f] = testutil.FileStatusFlags(t, f)
		}
	}

	// Register the sockets with tubectl
	tubectl := tubectlTestCall{
		NetNS:    netns,
		ExecNS:   netns,
		Cmd:      "register",
		Args:     []string{"svc-label"},
		Env:      map[string]string{"LISTEN_FDS": "2"},
		ExtraFds: fds,
	}

	_, err := tubectl.Run(t)
	if err != nil {
		t.Fatalf("failed to run tubectl: %v", err)
	}

	for _, f := range fds {
		if f == nil {
			continue
		}

		if have := testutil.FileStatusFlags(t, f); have != flags[f] {
			t.Fatalf("file status flags of %v changed: %d != %d", f, have, flags[f])
		}
	}

	// Open the dispatcher and verify the numer of destinations
	dp := mustOpenDispatcher(t, netns)

	dests := destinations(t, dp)
	if len(dests) != len(fds) {
		t.Fatalf("expected %v registered destination(s), have %v", len(fds), len(dests))
	}

	for _, f := range fds {
		cookie := mustSocketCookie(t, f)
		if _, ok := dests[cookie]; !ok {
			t.Fatalf("expected registered destination for socket %v", cookie)
		}
	}

	tubectl = tubectlTestCall{
		NetNS:  netns,
		ExecNS: netns,
		Cmd:    "unregister",
		Args:   []string{"svc-label", "ipv4", "tcp"},
	}

	_, err = tubectl.Run(t)
	if err != nil {
		t.Fatalf("failed to run tubectl: %v", err)
	}

	// Verify the numer of destinations, should only be 1 left
	dests = destinations(t, dp)
	if len(dests) != 1 {
		t.Fatalf("unexpected number of sockets, wanted 1, got %v", len(dests))
	}

	// First FD should not have a destination
	cookie := mustSocketCookie(t, fds[0])
	if _, ok := dests[cookie]; ok {
		t.Fatalf("expected no destination for socket %v", cookie)
	}

	// Second FD should have a destination
	cookie = mustSocketCookie(t, fds[1])
	if _, ok := dests[cookie]; !ok {
		t.Fatalf("expected destination for socket %v", cookie)
	}
}

func TestUnregisterNoSocket(t *testing.T) {
	// Generate a new netns/dispatcher for the test
	netns := mustReadyNetNS(t)

	tubectl := tubectlTestCall{
		NetNS:  netns,
		ExecNS: netns,
		Cmd:    "unregister",
		Args:   []string{"svc-label", "ipv4", "tcp"},
	}

	_, err := tubectl.Run(t)
	if err == nil {
		t.Fatal("unregister without sockets must return error")
	}
}

func TestUnregisterArgs(t *testing.T) {
	for tc, args := range map[string][]string{
		"too-little": {"svc-label", "ipv4"},
		"too-many":   {"svc_label", "ipv4", "tcp", "foo"},
	} {
		t.Run(tc, func(t *testing.T) {
			netns := mustReadyNetNS(t)

			tubectl := tubectlTestCall{
				NetNS:  netns,
				ExecNS: netns,
				Cmd:    "unregister",
				Args:   args,
			}

			_, err := tubectl.Run(t)
			if err == nil {
				t.Fatal("unregister must reject incorrect number of args")
			}
		})
	}
}
