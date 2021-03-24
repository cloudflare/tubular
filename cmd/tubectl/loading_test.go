package main

import (
	"strings"
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

func TestUpgrade(t *testing.T) {
	netns := mustReadyNetNS(t)

	upgrade := tubectlTestCall{
		NetNS: netns,
		Cmd:   "upgrade",
		Effective: []cap.Value{
			cap.SYS_ADMIN, cap.NET_ADMIN,
		},
	}

	output := upgrade.MustRun(t)
	if !strings.Contains(output.String(), Version) {
		t.Error("Output doesn't contain version")
	}
}
