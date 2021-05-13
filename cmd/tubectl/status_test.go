package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"code.cfops.it/sys/tubular/internal"
	"github.com/containernetworking/plugins/pkg/ns"
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

func TestListFilteredByLabel(t *testing.T) {
	netns := mustReadyNetNS(t)

	dp := mustOpenDispatcher(t, netns)
	mustAddBinding(t, dp, "foo", internal.TCP, "::1", 80)
	sock := makeListeningSocket(t, netns, "tcp")
	mustRegisterSocket(t, dp, "foo", sock)
	dp.Close()

	output, err := testTubectl(t, netns, "list", "foo")
	if err != nil {
		t.Fatal("Can't execute list foo:", err)
	}

	if !strings.Contains(output.String(), "foo") {
		t.Error("Output of list doesn't contain label foo")
	}

	output, err = testTubectl(t, netns, "list", "bar")
	if err != nil {
		t.Fatal("Can't execute list bar:", err)
	}

	if strings.Contains(output.String(), "foo") {
		t.Error("Output of list contains label foo, even though it should be filtered")
	}
}

func TestMetrics(t *testing.T) {
	netns := mustReadyNetNS(t)

	tubectl := tubectlTestCall{
		NetNS:     netns,
		Cmd:       "metrics",
		Args:      []string{"127.0.0.1", "0"},
		Listeners: make(chan net.Listener, 1),
	}

	tubectl.Start(t)

	var ln net.Listener
	select {
	case ln = <-tubectl.Listeners:
	case <-time.After(time.Second):
		t.Fatal("tubectl isn't listening after one second")
	}

	client := http.Client{Timeout: 5 * time.Second}
	addr := fmt.Sprintf("http://%s/metrics", ln.Addr().String())
	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			res, err := client.Get(addr)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()

			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatal("Can't ready body:", err)
			}

			if !bytes.Contains(body, []byte("# HELP ")) {
				t.Error("Output doesn't contain prometheus export format")
			}

			if !bytes.Contains(body, []byte("# TYPE tubular_")) {
				t.Error("Output doesn't contain tubular prefix")
			}

			if !bytes.Contains(body, []byte("# TYPE build_info")) {
				t.Error("Output doesn't contain unprefixed build_info")
			}
		})
	}
}

func TestMetricsInvalidArgs(t *testing.T) {
	netns, err := ns.GetCurrentNS()
	if err != nil {
		t.Fatal(err)
	}

	_, err = testTubectl(t, netns, "metrics")
	if err == nil {
		t.Error("metrics command accepts no arguments")
	}

	_, err = testTubectl(t, netns, "metrics", "127.0.0.1")
	if err == nil {
		t.Error("metrics command accepts missing port")
	}
}
