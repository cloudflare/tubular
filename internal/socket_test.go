package internal

import (
	"bytes"
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadWriteSocket(t *testing.T) {
	srv, cli := unixSeqpacketPair(t)

	send := []byte("boo")
	_, err := WriteToSocket(cli, send, os.Stderr)
	if err != nil {
		t.Fatal("Can't write to socket:", err)
	}

	buf := make([]byte, len(send))
	n, uid, rcvFile, err := ReadFromSocket(srv, buf)
	if err != nil {
		t.Fatal("Can't read from socket:", err)
	}

	buf = buf[:n]
	if !bytes.Equal(buf[:n], send) {
		t.Errorf("Received data doesn't match sent: %s != %s", string(send), string(buf))
	}

	if current := unix.Getuid(); uid != current {
		t.Errorf("Expected uid %d, got %d", current, uid)
	}

	if rcvFile == nil {
		t.Fatal("Expected file to be non-nil")
	}
	defer rcvFile.Close()

	sendStat, err := os.Stderr.Stat()
	if err != nil {
		t.Fatal("Can't stat file:", err)
	}

	rcvStat, err := rcvFile.Stat()
	if err != nil {
		t.Fatal("Can't stat file:", err)
	}

	if rcvStat.Sys().(*syscall.Stat_t).Ino != sendStat.Sys().(*syscall.Stat_t).Ino {
		t.Error("File inodes do not match", rcvStat.Sys().(*syscall.Stat_t).Ino, sendStat.Sys().(*syscall.Stat_t).Ino)
	}
}

func unixSeqpacketPair(t *testing.T) (srv, cli *net.UnixConn) {
	t.Helper()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	err = unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
	if err != nil {
		t.Fatalf("SetsockoptInt: %v", err)
	}

	srvFile := os.NewFile(uintptr(fds[0]), "server")
	defer srvFile.Close()

	srvConn, err := net.FileConn(srvFile)
	if err != nil {
		t.Fatal("server FileConn:", err)
	}
	t.Cleanup(func() { srvConn.Close() })

	cliFile := os.NewFile(uintptr(fds[1]), "client")
	defer cliFile.Close()

	cliConn, err := net.FileConn(cliFile)
	if err != nil {
		t.Fatal("client FileConn:", err)
	}
	t.Cleanup(func() { cliConn.Close() })

	return srvConn.(*net.UnixConn), cliConn.(*net.UnixConn)
}
