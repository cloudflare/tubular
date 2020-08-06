package main

import "testing"

func TestLoadUnload(t *testing.T) {
	mustTestTubectl(t, "load")
	mustTestTubectl(t, "unload")
}
