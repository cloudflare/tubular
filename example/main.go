package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"time"

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
				sa, err := unix.ParseOrigDstAddr(&scms[0])
				if err != nil {
					fmt.Fprintln(os.Stderr, "retrieve destination:", err)
					continue
				}

				// encode the destination address into a cmsg.
				var info []byte
				switch v := sa.(type) {
				case *unix.SockaddrInet4:
					info = unix.PktInfo4(&unix.Inet4Pktinfo{
						Spec_dst: v.Addr,
					})

				case *unix.SockaddrInet6:
					info = unix.PktInfo6(&unix.Inet6Pktinfo{
						Addr: v.Addr,
					})
				}

				// reply from the original destination address.
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
