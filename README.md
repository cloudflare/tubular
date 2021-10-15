tubular
===

The control plane for BPF socket lookup. Steers traffic that arrives via the
[tubes of the Internet][1] to processes running on the machine. Its much more
flexible than traditional BSD `bind` semantics:

* You can bind to all ports on an IP
* You can bind to a subnet instead of an IP
* You can bind to all ports on a subnet

Quickstart
---

```sh
# Install and load tubular
$ go install code.cfops.it/sys/tubular/cmd/tubectl@latest
$ sudo tubectl load

# Send port 4321 traffic on all loopback IPs to the foo label.
$ sudo tubectl bind foo tcp 127.0.0.0/8 4321

# Set up a server and register the listening socket under the foo label
$ nc -k -l 127.0.0.1 9999 &
$ sudo tubectl register-pid $! foo tcp 127.0.0.1 9999

# Send a message!
$ echo $USER | nc -q 1 127.0.0.23 4321
```

The real power is in the `bind` command.

```sh
# Send HTTP traffic on a /24 to the foo label.
$ sudo tubectl bind foo tcp 127.0.0.0/24 80
$ echo $USER | nc -q 1 127.0.0.123 80

# Send TCP traffic on all ports of a specific IP to the foo label.
$ sudo tubectl bind foo tcp 127.0.0.22 0
$ echo $USER | nc -q 1 127.0.0.22 $((1 + $RANDOM))
```

Integrating with tubular
---

TCP servers are compatible with tubular out of the box. For UDP you need to
set some additional socket options and change the way you send replies.

In general, you will have to **register your sockets with tubular**. The easiest
way is to use `tubectl register-pid` combined with a systemd service of
[Type=notify][3]. It's also possible to use systemd socket activation combined
with `tubectl register`, but this setup is more complicated than `register-pid`.

**[The example](example/README.md) shows how to use `register-pid` with a TCP
and UDP echo server.**

Testing
---

`tubular` requires some bleeding edge Linux features and therefore runs tests
in a VM. You will need QEMU and [virtme][2] installed.

```sh
$ make test
# Without the vm, only works if your kernel is recent enough.
$ go test -exec sudo ./...
```

[1]: https://en.wikipedia.org/wiki/Series_of_tubes
[2]: https://github.com/amluto/virtme/
[3]: https://www.freedesktop.org/software/systemd/man/systemd.service.html#Type=
