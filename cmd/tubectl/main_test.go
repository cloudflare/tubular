package main

import (
	"bytes"
	"os"
	"strings"
	"syscall"
	"testing"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/internal/testutil"
	_ "code.cfops.it/sys/tubular/internal/testutil"
	"github.com/containernetworking/plugins/pkg/ns"
)

func testTubectl(tb testing.TB, netns ns.NetNS, cmd string, args ...string) (*bytes.Buffer, error) {
	tb.Helper()

	tc := tubectlTestCall{
		NetNS: netns,
		Cmd:   cmd,
		Args:  args,
	}
	return tc.Run(tb)
}

func mustTestTubectl(tb testing.TB, netns ns.NetNS, cmd string, args ...string) {
	tb.Helper()

	if _, err := testTubectl(tb, netns, cmd, args...); err != nil {
		tb.Fatal("Can't execute tubectl:", err)
	}
}

func mustReadyNetNS(tb testing.TB) ns.NetNS {
	tb.Helper()

	netns := testutil.NewNetNS(tb)
	dp, err := internal.CreateDispatcher(netns.Path(), "/sys/fs/bpf")
	if err != nil {
		tb.Fatal(err)
	}
	path := dp.Path
	if err := dp.Close(); err != nil {
		tb.Fatal("Can't close dispatcher:", err)
	}
	tb.Cleanup(func() { os.RemoveAll(path) })
	return netns
}

func mustOpenDispatcher(tb testing.TB, netns ns.NetNS) *internal.Dispatcher {
	tb.Helper()
	dp, err := internal.OpenDispatcher(netns.Path(), "/sys/fs/bpf")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { dp.Close() })
	return dp
}

func mustAddBinding(tb testing.TB, dp *internal.Dispatcher, label string, proto internal.Protocol, prefix string, port uint16) {
	tb.Helper()

	bind, err := internal.NewBinding(label, proto, prefix, port)
	if err != nil {
		tb.Fatal(err)
	}

	err = dp.AddBinding(bind)
	if err != nil {
		tb.Fatal("Can't add binding:", err)
	}
}

type (
	testEnv map[string]string
	testFds []syscall.Conn
)

// tubectlTestCall represents a call to tubectl main function from a test.
type tubectlTestCall struct {
	NetNS ns.NetNS
	Cmd   string
	Args  []string

	// Env specifies the enviroment variables for tubectl test call, which
	// values can be retrived with env.getenv. os.Getenv is unaffected by this
	// setting.
	Env testEnv

	// ExtraFds specifies additonal open file descriptors to be returned by
	// env.newFile for the duration tubectl test call. It does not include
	// standard input, standard output, or standard error. If non-nil, entry i
	// becomes file descriptor 3+i.
	ExtraFds testFds
}

func (tc *tubectlTestCall) Run(tb testing.TB) (*bytes.Buffer, error) {
	tb.Helper()

	output := new(bytes.Buffer)
	env := env{
		stdout: output,
		stderr: output,
		osFns: osFns{
			getenv:  func(key string) string { return tc.getenv(key) },
			newFile: func(fd uintptr, name string) *os.File { return tc.newFile(fd, name) },
		},
	}
	args := []string{"-netns", tc.NetNS.Path(), tc.Cmd}
	args = append(args, tc.Args...)

	err := tubectl(env, args)
	tb.Logf("tubectl %s\n%s", strings.Join(args, " "), output)
	return output, err
}

func (tc *tubectlTestCall) getenv(key string) string {
	if v, ok := tc.Env[key]; ok {
		return v
	}
	return ""
}

func (tc *tubectlTestCall) newFile(fd uintptr, name string) *os.File {
	var (
		firstExtraFd = uintptr(syscall.Stderr + 1)
		lastExtraFd  = uintptr(syscall.Stderr + len(tc.ExtraFds))
	)
	if firstExtraFd <= fd && fd <= lastExtraFd {
		i := fd - firstExtraFd
		c := tc.ExtraFds[i]
		if c == nil {
			return nil
		}
		rc, err := c.SyscallConn()
		if err != nil {
			return nil
		}

		var file *os.File
		err = rc.Control(func(fd uintptr) {
			file = os.NewFile(fd, name)
		})
		if err != nil {
			return nil
		}
		return file
	}
	return nil
}
