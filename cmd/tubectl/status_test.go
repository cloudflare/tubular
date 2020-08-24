package main

import (
	"strings"
	"testing"

	"code.cfops.it/sys/tubular/internal"
)

func TestList(t *testing.T) {
	netns := mustReadyNetNS(t)

	dp := mustOpenDispatcher(t, netns)
	mustAddBinding(t, dp, "foo", internal.TCP, "::1", 80)
	dp.Close()

	output, err := testTubectl(t, netns, "list")
	if err != nil {
		t.Fatal("Can't execute list:", err)
	}

	out := output.String()
	t.Log(out)

	if !strings.Contains(out, "foo") {
		t.Error("Output of list doesn't contain label foo")
	}
}
