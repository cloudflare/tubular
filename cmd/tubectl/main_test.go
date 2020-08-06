package main

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"code.cfops.it/sys/tubular/internal"
	"code.cfops.it/sys/tubular/internal/testutil"
)

func TestMain(m *testing.M) {
	testutil.ExecuteInNetns()
	if err := internal.SetLockedMemoryLimits(10 * 1024 * 1024); err != nil {
		fmt.Fprintln(os.Stderr, "Can't raise rlimit, tests may fail:", err)
	}
	os.Exit(m.Run())
}

func testTubectl(tb testing.TB, args ...string) error {
	stdio := new(bytes.Buffer)
	if err := tubectl(stdio, stdio, args...); err != nil {
		tb.Helper()
		tb.Logf("Output:\n%s", stdio.String())
		return err
	}
	return nil
}

func mustTestTubectl(tb testing.TB, args ...string) {
	if err := testTubectl(tb, args...); err != nil {
		tb.Helper()
		tb.Fatal("Can't execute tubectl:", err)
	}
}
