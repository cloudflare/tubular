tubular echo server
===

This TCP and UDP echo server shows how to integrate a service with tubular. The
trickiest part is to figure out when it's safe to invoke `tubectl register-pid`.
`register-pid` will fail if we call it before the echo server has bound its sockets.

We therefore use a transient systemd service with `Type=notify` to determine when
to call `tubectl register-pid`. See [sd_notify][1] for details on the mechanism.

TCP servers don't require modification, while dispatching UDP traffic using tubular
will require modifying your application.

Support for UDP via IPv4 boils down to:

* setsockopt(SOL_IP, IP_RECVORIGDSTADDR, 1)
* recvmsg() followed by parsing a cmsg with level = SOL_IP and type = IP_ORIGDSTADDR
* sendmsg() with a cmsg with level = SOL_IP and type = IP_PKTINFO

The IP_PKTINFO cmsg contains the original destination address.

UDP via IPv6 is the same, except that you will have to set IPV6_FREEBIND:

* setsockopt(SOL_IPV6, IPV6_RECVORIGDSTADDR, 1)
* setsockopt(SOL_IPV6, IPV6_FREEBIND, 1)
* recvmsg() followed by parsing a cmsg with level = SOL_IPV6 and type = IPV6_ORIGDSTADDR
* sendmsg() with a cmsg with level = SOL_IPV6 and type = IPV6_PKTINFO

This doesn't enable port wildcards for UDP, but the code required is quite
involved and therefore not covered here.

Setup
---


```sh
# load tubular & create bindings
go run -exec sudo ../cmd/tubectl load
go run -exec sudo ../cmd/tubectl bind example tcp 127.0.0.128/25 0
go run -exec sudo ../cmd/tubectl bind example udp 127.0.0.128/25 1234
sudo ip -6 route add local 2001:db8::/64 dev lo
go run -exec sudo ../cmd/tubectl bind example tcp 2001:db8::/64 0
go run -exec sudo ../cmd/tubectl bind example udp 2001:db8::/64 1234

# run server and register sockets
sudo systemd-run -G -d -E HOME="$(mktemp -d)" -u tubular-echo-server \
	-p Type=notify -p NotifyAccess=all \
	-p ExecStartPost="go run ../cmd/tubectl register-pid \$MAINPID example tcp 127.0.0.1 1234" \
	-p ExecStartPost="go run ../cmd/tubectl register-pid \$MAINPID example udp 127.0.0.1 1234" \
	-p ExecStartPost="go run ../cmd/tubectl register-pid \$MAINPID example tcp ::1 1234" \
	-p ExecStartPost="go run ../cmd/tubectl register-pid \$MAINPID example udp ::1 1234" \
	go run main.go
```

You should now have the following bindings and sockets present:

```
$ go run -exec sudo ../cmd/tubectl list
opened dispatcher at /sys/fs/bpf/4026532008_dispatcher
Bindings:
 protocol         prefix port   label
      tcp 127.0.0.128/25    0 example
      tcp  2001:db8::/64    0 example
      udp 127.0.0.128/25 1234 example
      udp  2001:db8::/64 1234 example

Destinations:
   label domain protocol  socket lookups misses errors
 example   ipv4      tcp sk:5004       0      0      0
 example   ipv4      udp sk:5005       0      0      0
 example   ipv6      tcp sk:3005       0      0      0
 example   ipv6      udp    sk:2       0      0      0
```

Time for some experimentation!

```
# send a TCP packet to a random port
echo $USER | nc -q 1 127.0.0.128 $((1 + $RANDOM))
# send a TCP packet to an different IP in 127.0.0.128/25
echo $USER | nc -q 1 127.0.0.242 $((1 + $RANDOM))
# send a UDP packet to an IP in one of the prefixes
echo $USER | nc -u 127.0.0.129 1234
echo $USER | nc -u 2001:db8::2342 1234
```

Once you are done experimenting you can clean up:

```sh
sudo systemctl stop tubular-echo-server
sudo ip -6 route del local 2001:db8::/64 dev lo
go run -exec sudo ../cmd/tubectl unload
```

[1]: https://www.freedesktop.org/software/systemd/man/sd_notify.html
