package main

import (
	"testing"

	"code.cfops.it/sys/tubular/internal/testutil"
)

func TestLoadUnload(t *testing.T) {
	netns := testutil.NewNetNS(t)

	mustTestTubectl(t, netns, "load")
	mustTestTubectl(t, netns, "unload")
}
