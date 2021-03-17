package main

import (
	"testing"

	"code.cfops.it/sys/tubular/internal/testutil"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func TestLoadUnload(t *testing.T) {
	netns := testutil.NewNetNS(t)

	load := tubectlTestCall{
		NetNS: netns,
		Cmd:   "load",
		Effective: []cap.Value{
			cap.SYS_ADMIN, cap.NET_ADMIN,
		},
	}
	load.MustRun(t)

	mustTestTubectl(t, netns, "unload")
}
