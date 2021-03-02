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
	sock := makeListeningSocket(t, netns, "tcp")
	mustRegisterSocket(t, dp, "foo", sock)
	dp.Close()

	output, err := testTubectl(t, netns, "list")
	if err != nil {
		t.Fatal("Can't execute list:", err)
	}

	outputStr := output.String()
	if !strings.Contains(outputStr, "foo") {
		t.Error("Output of list doesn't contain label foo")
	}

	cookie := mustSocketCookie(t, sock)
	if !strings.Contains(outputStr, cookie.String()) {
		t.Error("Output of list doesn't contain", cookie)
	}

	output2, err := testTubectl(t, netns, "list")
	if err != nil {
		t.Fatal(err)
	}

	output2Str := output2.String()
	if output2Str != outputStr {
		t.Log(outputStr)
		t.Log(output2Str)
		t.Error("The output of list isn't stable across invocations")
	}
}
