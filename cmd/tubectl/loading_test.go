package main

import (
	"strings"
	"testing"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/internal/testutil"
)

func TestLoadUnload(t *testing.T) {
	netns := testutil.NewNetNS(t)

	load := tubectlTestCall{
		NetNS:     netns,
		Cmd:       "load",
		Effective: internal.CreateCapabilities,
	}
	load.MustRun(t)

	mustTestTubectl(t, netns, "unload")
}

func TestUpgrade(t *testing.T) {
	netns := mustReadyNetNS(t)

	upgrade := tubectlTestCall{
		NetNS:     netns,
		Cmd:       "upgrade",
		Effective: internal.CreateCapabilities,
	}

	output := upgrade.MustRun(t)
	if !strings.Contains(output.String(), Version) {
		t.Error("Output doesn't contain version")
	}
}
