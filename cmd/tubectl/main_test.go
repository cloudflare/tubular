package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/internal/log"
	"code.cfops.it/sys/tubular/internal/sysconn"
	"code.cfops.it/sys/tubular/internal/testutil"
	_ "code.cfops.it/sys/tubular/internal/testutil"
	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
)

func TestHelp(t *testing.T) {
	cmd := tubectlTestCall{
		Args: []string{"-help"},
	}

	a := cmd.MustRun(t)
	b := cmd.MustRun(t)

	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("-help output isn't stable")
	}
}

func testTubectl(tb testing.TB, netns ns.NetNS, cmd string, args ...string) (*bytes.Buffer, error) {
	tc := tubectlTestCall{
		NetNS: netns,
		Cmd:   cmd,
		Args:  args,
	}
	return tc.Run(tb)
}

func mustTestTubectl(tb testing.TB, netns ns.NetNS, cmd string, args ...string) *bytes.Buffer {
	tc := tubectlTestCall{
		NetNS: netns,
		Cmd:   cmd,
		Args:  args,
	}
	return tc.MustRun(tb)
}

func mustReadyNetNS(tb testing.TB) ns.NetNS {
	tb.Helper()

	netns := testutil.NewNetNS(tb)
	mustLoadDispatcher(tb, netns)
	return netns
}

func mustLoadDispatcher(tb testing.TB, netns ns.NetNS) {
	tb.Helper()

	dp, err := internal.CreateDispatcher(log.Discard, netns.Path(), "/sys/fs/bpf")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { os.RemoveAll(dp.Path) })

	if err := dp.Close(); err != nil {
		tb.Fatal("Can't close dispatcher:", err)
	}
}

func mustOpenDispatcher(tb testing.TB, netns ns.NetNS) *internal.Dispatcher {
	tb.Helper()
	dp, err := internal.OpenDispatcher(log.Discard, netns.Path(), "/sys/fs/bpf")
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

func mustRegisterSocket(tb testing.TB, dp *internal.Dispatcher, label string, file syscall.Conn) *internal.Destination {
	tb.Helper()

	dest, _, err := dp.RegisterSocket(label, file)
	if err != nil {
		tb.Fatal("Can't register socket:", err)
	}

	return dest
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

	// Listeners receives the created listeners if the channel is not nil.
	Listeners chan net.Listener

	// Context cancelled when test call should return. Controlled with Start() and Stop().
	ctx    context.Context
	cancel context.CancelFunc

	// Channel for passing error from Run(). Use via Start() and Stop().
	errs chan error
}

func (tc *tubectlTestCall) Run(tb testing.TB) (*bytes.Buffer, error) {
	tb.Helper()

	output := new(log.Buffer)
	ctx := tc.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	env := env{
		stdout: output,
		stderr: output,
		ctx:    ctx,
		getenv: func(key string) string { return tc.getenv(key) },
		newFile: func(fd uintptr, name string) *os.File {
			return tc.newFile(fd, name)
		},
		listen: func(network, addr string) (net.Listener, error) {
			ln, err := net.Listen(network, addr)
			if err != nil {
				tb.Error("Listen failed:", err)
				return nil, err
			}

			if tc.Listeners != nil {
				tc.Listeners <- ln
			}
			return ln, nil
		},
	}
	var args []string
	if tc.NetNS != nil {
		args = append(args, "-netns", tc.NetNS.Path())
	}
	if tc.Cmd != "" {
		args = append(args, tc.Cmd)
	}
	args = append(args, tc.Args...)

	err := tubectl(env, args)
	tb.Logf("tubectl %s\n%s", strings.Join(args, " "), output)
	return &output.Buffer, err
}

func (tc *tubectlTestCall) MustRun(tb testing.TB) *bytes.Buffer {
	tb.Helper()

	output, err := tc.Run(tb)
	if err != nil {
		tb.Fatal("Error from tubectl:", err)
	}

	return output
}

func (tc *tubectlTestCall) Start(tb testing.TB) {
	if tc.ctx != nil {
		return // already started
	}

	tc.ctx, tc.cancel = context.WithCancel(context.Background())
	tc.errs = make(chan error, 1)

	go func() {
		_, err := tc.Run(tb)
		tc.errs <- err
		close(tc.errs)
	}()
	runtime.Gosched()
}

func (tc *tubectlTestCall) Stop() error {
	if tc.ctx == nil {
		return nil // not started
	}

	tc.cancel()
	tc.ctx = nil

	err := <-tc.errs
	return err
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

		f, _ := dupFile(c)
		return f
	}
	return nil
}

// Creates an os.File for the same file _description_, but not the same file
// _descriptor_, as represented by passed syscall.Conn.
func dupFile(old syscall.Conn) (*os.File, error) {
	newFd, err := sysconn.ControlInt(old, func(fd int) (int, error) {
		return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	})
	if err != nil {
		return nil, err
	}

	return os.NewFile(uintptr(newFd), ""), nil
}
