package main

import (
	"bytes"
	"testing"
)

func TestOptionalArgs(t *testing.T) {
	var buf bytes.Buffer

	fs := newFlagSet(&buf, "test", "a", "--", "b")
	if err := fs.Parse([]string{"foo"}); err != nil {
		t.Fatal("Can't invoke without optional argument")
	}

	if err := fs.Parse([]string{"foo", "bar"}); err != nil {
		t.Fatal("Can't invoke with optional argument")
	}

	if err := fs.Parse([]string{"foo", "bar", "baz"}); err == nil {
		t.Fatal("Accepted extraneous argument")
	}
}

func TestTrimLeadingTabsAndSpace(t *testing.T) {
	const want = "a\n\nb\nc\nd"
	have := trimLeadingTabsAndSpace("\na\n\n\tb\n\t\tc\n\t\t\td\n")
	if have != want {
		t.Errorf("Want %q, have %q", want, have)
	}
}
