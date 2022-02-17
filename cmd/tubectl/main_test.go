package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/cloudflare/tubular/internal"
	"github.com/cloudflare/tubular/internal/log"
	"github.com/cloudflare/tubular/internal/sysconn"
	"github.com/cloudflare/tubular/internal/testutil"

	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func init() {
	testutil.EnterUnprivilegedMode()
}

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

func TestSubcommandHelp(t *testing.T) {
	for _, cmd := range cmds {
		t.Run(cmd.name, func(t *testing.T) {
			var output log.Buffer
			err := cmd.fn(&env{stdout: &output, stderr: &output}, "-help")
			t.Log(output.String())
			if !errors.Is(err, flag.ErrHelp) {
				t.Error("Doesn't return ErrHelp")
			}
		})
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

	var dp *internal.Dispatcher
	err := testutil.WithCapabilities(func() (err error) {
		dp, err = internal.CreateDispatcher(netns.Path(), "/sys/fs/bpf")
		return
	}, internal.CreateCapabilities...)
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
	dp, err := internal.OpenDispatcher(netns.Path(), "/sys/fs/bpf", false)
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
	// The network namespace from which to load the dispatcher.
	NetNS ns.NetNS

	// The network namespace from which to execute the test call. Defaults to
	// the current namespace.
	ExecNS ns.NetNS

	Cmd  string
	Args []string

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

	// Effective lists the capabilities required for this call. The effective
	// set isn't changed if the slice is empty.
	Effective []cap.Value
}

func (tc *tubectlTestCall) Run(tb testing.TB) (*bytes.Buffer, error) {
	output := new(log.Buffer)
	if err := tc.run(tb, context.Background(), output); err != nil {
		return nil, err
	}

	tb.Logf("tubectl %s %s\n%s", tc.Cmd, strings.Join(tc.Args, " "), output)
	return &output.Buffer, nil
}

func (tc *tubectlTestCall) run(tb testing.TB, ctx context.Context, output log.Logger) error {
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

	flags := make(map[syscall.Conn]int)
	for _, f := range tc.ExtraFds {
		if f != nil {
			flags[f] = testutil.FileStatusFlags(tb, f)
		}
	}

	exec := tc.ExecNS
	if exec == nil {
		exec = testutil.CurrentNetNS(tb)
	}

	var err error
	testutil.JoinNetNS(tb, exec, func() error {
		err = tubectl(env, args)
		return nil
	}, tc.Effective...)

	for _, f := range tc.ExtraFds {
		if f == nil {
			continue
		}

		if have := testutil.FileStatusFlags(tb, f); have != flags[f] {
			tb.Fatalf("file status flags of %v changed: %d != %d", f, have, flags[f])
		}
	}

	return err
}

func (tc *tubectlTestCall) MustRun(tb testing.TB) *bytes.Buffer {
	tb.Helper()

	output, err := tc.Run(tb)
	if err != nil {
		tb.Fatal("Error from tubectl:", err)
	}

	return output
}

func (tc *tubectlTestCall) Start(tb testing.TB) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	tb.Cleanup(cancel)
	done := make(chan struct{})

	go func() {
		defer close(done)

		if err := tc.run(tb, ctx, log.Discard); err != nil {
			select {
			case <-ctx.Done():
			default:
				tb.Errorf("Error from tubectl %s: %s", tc.Cmd, err)
			}
		}
	}()

	runtime.Gosched()
	return func() {
		cancel()
		<-done
	}
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
