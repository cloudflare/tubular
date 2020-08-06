package testutil

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// ExecuteInNetns executes the current binary in a new network namespace.
//
// Must be called from main or TestMain. The new namespace has lo configured.
// The function aborts the process when encountering an error.
func ExecuteInNetns() {
	const key = "IN_NEW_NETNS"
	// We want to run these tests in a separate network namespace.
	// To do that reliably, we want to have the process and all its threads
	// to be executed in that namespace. So we execute ourselves and set an
	// environment variable so the nested execution knows not to re-execute.
	if os.Getenv(key) == "" {
		cmd := exec.Cmd{
			Path:   os.Args[0],
			Args:   os.Args,
			Env:    append(os.Environ(), key+"=true"),
			Stdin:  os.Stdin,
			Stdout: os.Stdout,
			Stderr: os.Stderr,
			SysProcAttr: &syscall.SysProcAttr{
				Cloneflags: syscall.CLONE_NEWNET,
			},
		}

		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: can't execute in new netns: %s\n", err)
			os.Exit(1)
		}

		os.Exit(0)
	}

	os.Setenv(key, "")

	// Make sure we have loopback configured
	cmd := exec.Command("ip", "link", "set", "dev", "lo", "up")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: can't bring up lo: %s\n", err)
		os.Exit(1)
	}
}
