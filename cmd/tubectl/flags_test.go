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
