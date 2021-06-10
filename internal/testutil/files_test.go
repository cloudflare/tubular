package testutil

import (
	"net"
	"testing"
)

func TestSpawnChildWithFiles(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	file, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ln.Close()

	flags := FileStatusFlags(t, file)
	pid := SpawnChildWithFiles(t, file)
	newFlags := FileStatusFlags(t, file)

	if pid == 0 {
		t.Error("Weird pid:", pid)
	}

	if newFlags != flags {
		t.Errorf("File status flags changed: 0x%x != 0x%x", newFlags, flags)
	}
}
