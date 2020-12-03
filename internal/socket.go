package internal

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// WriteToSocket writes a message with an accompanying file descriptor to a
// Unix socket.
//
// It's valid to pass a nil file. Each call to this function performs exactly
// one write on conn.
func WriteToSocket(conn *net.UnixConn, p []byte, file *os.File) (int, error) {
	if file == nil {
		return conn.Write(p)
	}

	sys, err := file.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("syscall conn: %s", err)
	}

	var writeErr error
	var n int
	err = sys.Control(func(fd uintptr) {
		oob := unix.UnixRights(int(fd))
		var oobn int
		n, oobn, writeErr = conn.WriteMsgUnix(p, oob, nil)
		if writeErr != nil {
			return
		}

		if oobn != len(oob) {
			writeErr = fmt.Errorf("short write of out-of-band data")
		}
	})
	if err != nil {
		return 0, fmt.Errorf("control: %s", err)
	}
	if writeErr != nil {
		return 0, writeErr
	}
	return n, nil
}

// ReadFromSocket reads a message, between zero and one file descriptors and
// the senders uid from a Unix socket.
//
// file is optional and may be nil. The function requires SO_PASSCRED to be
// set on conn, so uid is always valid if no error is returned.
//
// Each call to this function performs exactly one read on conn.
func ReadFromSocket(conn *net.UnixConn, p []byte) (n, uid int, file *os.File, err error) {
	const sizeofInt32 = 4
	rightsLen := unix.CmsgSpace(1 * sizeofInt32)
	credsLen := unix.CmsgSpace(unix.SizeofUcred)

	oob := make([]byte, rightsLen+credsLen)
	n, oobn, _, _, err := conn.ReadMsgUnix(p, oob)
	if err != nil {
		return 0, 0, nil, err
	}

	scms, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, 0, nil, fmt.Errorf("parse control messages: %s", err)
	}

	var creds *unix.Ucred
	// Don't bail out while processing SCMs, we need to make sure that we don't
	// leak file descriptors.
	for _, scm := range scms {
		if scm.Header.Level != unix.SOL_SOCKET {
			err = fmt.Errorf("unrecognised cmsg level: %d", scm.Header.Level)
			continue
		}

		switch scm.Header.Type {
		case unix.SCM_CREDENTIALS:
			creds, err = unix.ParseUnixCredentials(&scm)
			if err != nil {
				err = fmt.Errorf("parse credentials: %s", err)
				continue
			}

		case unix.SCM_RIGHTS:
			var rights []int
			rights, err = unix.ParseUnixRights(&scm)
			if err != nil {
				err = fmt.Errorf("parse rights: %s", err)
				continue
			}

			if len(rights) > 1 || file != nil {
				for _, fd := range rights {
					// Don't let the remote end flood us with fds
					unix.Close(fd)
				}
				err = fmt.Errorf("can't handle more than one file descriptor")
				continue
			}

			file = os.NewFile(uintptr(rights[0]), "cmsg fd")

		default:
			err = fmt.Errorf("unrecognised cmsg type: %d", scm.Header.Type)
		}
	}

	if err != nil {
		file.Close()
		return 0, 0, nil, err
	}

	if creds == nil {
		file.Close()
		return 0, 0, nil, fmt.Errorf("missing credentials")
	}

	return n, int(creds.Uid), file, nil
}
