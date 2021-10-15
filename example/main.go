package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"time"
	"unsafe"

	"code.cfops.it/sys/tubular/pkg/sysconn"

	"golang.org/x/sys/unix"
)

func run() error {
	// Set up tcp4 and tcp6 listeners.
	tcp4, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234})
	if err != nil {
		return err
	}
	defer tcp4.Close()

	tcp6, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback, Port: 1234})
	if err != nil {
		return err
	}
	defer tcp6.Close()

	// Set up a udp4 listener and enable IP_RECVORIGDSTADDR on it.
	udp4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234})
	if err != nil {
		return err
	}
	defer udp4.Close()

	err = sysconn.Control(udp4, func(fd int) error {
		return unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
	})
	if err != nil {
		return err
	}

	// Set up a udp6 listener and enable IPV6_RECVORIGDSTADDR, IPV6_FREEBIND on it.
	udp6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 1234})
	if err != nil {
		return err
	}
	defer udp6.Close()

	err = sysconn.Control(udp6, func(fd int) error {
		err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
		if err != nil {
			return err
		}
		return unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_FREEBIND, 1)
	})
	if err != nil {
		return err
	}

	// We've bound the listening sockets, notify systemd that the process has
	// finished start up. This will execute any ExecStartPost commands, which
	// allows us to run register-pid at the appropriate time.
	_ = exec.Command("systemd-notify", "--ready", fmt.Sprintf("--pid=%d", os.Getpid())).Run()

	// Start goroutines that service the listeners.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// TCP support.
	for _, ln := range []*net.TCPListener{tcp4, tcp6} {
		go func(ln *net.TCPListener) {
			msg := make([]byte, 1024)

			for {
				conn, err := ln.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
					}
					fmt.Fprintln(os.Stderr, "accept error:", err)
					continue
				}

				conn.SetDeadline(time.Now().Add(time.Second))
				n, err := conn.Read(msg)
				if err != nil {
					fmt.Println("failed read:", err)
					goto next
				}

				_, err = conn.Write(append([]byte("hi "), msg[:n]...))
				if err != nil {
					fmt.Println("failed to respond:", err)
				}

			next:
				conn.Close()
			}
		}(ln)
	}

	// UDP support.
	for _, conn := range []*net.UDPConn{udp4, udp6} {
		go func(conn *net.UDPConn) {
			msg := make([]byte, 1024)
			oob := make([]byte, unix.CmsgSpace(unix.SizeofSockaddrInet6))

			for {
				n, oobn, _, remote, err := conn.ReadMsgUDP(msg, oob)
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
					}
					fmt.Fprintln(os.Stderr, "receive error:", err)
					continue
				}

				// oob contains socket control messages which we need to parse.
				scms, err := unix.ParseSocketControlMessage(oob[:oobn])
				if err != nil {
					fmt.Fprintln(os.Stderr, "parse control message:", err)
					continue
				}

				// retrieve the destination address from the SCM.
				dst, err := retrieveOrigdstaddr(&scms[0])
				if err != nil {
					fmt.Fprintln(os.Stderr, "retrieve destination:", err)
					continue
				}
				fmt.Fprintln(os.Stderr, "received packet on", dst)

				// Encode the destination address into a cmsg and use it to
				// send a reply.
				info := pktInfo(dst.IP)
				_, _, err = conn.WriteMsgUDP(append([]byte("hi "), msg[:n]...), info, remote)
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
					}
					fmt.Fprintln(os.Stderr, "failed to respond:", err)
				}
			}
		}(conn)
	}

	<-ctx.Done()
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func retrieveOrigdstaddr(scm *unix.SocketControlMessage) (*net.UDPAddr, error) {
	var rawIP []byte
	var port int
	h := scm.Header
	switch {
	case h.Level == unix.SOL_IP && h.Type == unix.IP_ORIGDSTADDR:
		var rsa unix.RawSockaddrInet4
		err := binary.Read(bytes.NewReader(scm.Data), binary.BigEndian, &rsa)
		if err != nil {
			return nil, err
		}
		rawIP = rsa.Addr[:]
		port = int(rsa.Port)

	case h.Level == unix.SOL_IPV6 && h.Type == unix.IPV6_ORIGDSTADDR:
		var rsa unix.RawSockaddrInet6
		err := binary.Read(bytes.NewReader(scm.Data), binary.BigEndian, &rsa)
		if err != nil {
			return nil, err
		}
		rawIP = rsa.Addr[:]
		port = int(rsa.Port)

	default:
		return nil, fmt.Errorf("unrecognized control message: %v %v", h.Level, h.Type)
	}

	ip := make(net.IP, len(rawIP))
	copy(ip, rawIP)

	return &net.UDPAddr{
		IP:   ip,
		Port: port,
	}, nil
}

func pktInfo(addr net.IP) []byte {
	if v4 := addr.To4(); v4 != nil {
		var info unix.Inet4Pktinfo
		copy(info.Spec_dst[:], v4)
		return unixInet4Pktinfo(&info)
	}

	var info unix.Inet6Pktinfo
	copy(info.Addr[:], addr.To16())
	return unixInet6Pktinfo(&info)
}

func unixInet4Pktinfo(info *unix.Inet4Pktinfo) []byte {
	b := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.SOL_IP
	h.Type = unix.IP_PKTINFO
	h.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
	*(*unix.Inet4Pktinfo)(unsafe.Pointer(uintptr(unsafe.Pointer(&b[0])) + uintptr(unix.CmsgLen(0)))) = *info
	return b
}

func unixInet6Pktinfo(info *unix.Inet6Pktinfo) []byte {
	b := make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.SOL_IPV6
	h.Type = unix.IPV6_PKTINFO
	h.SetLen(unix.CmsgLen(unix.SizeofInet6Pktinfo))
	*(*unix.Inet6Pktinfo)(unsafe.Pointer(uintptr(unsafe.Pointer(&b[0])) + uintptr(unix.CmsgLen(0)))) = *info
	return b
}
