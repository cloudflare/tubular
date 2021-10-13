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
$ make
# Load tubular
$ sudo ./bin/amd64/tubectl load
# Send HTTP traffic to the foo label.
$ sudo ./bin/amd64/tubectl bind foo tcp 127.0.0.1 80
# Set up a server and register the listening socket under the foo label
$ nc -k -l 127.0.0.1 9999 &
$ sudo ./bin/amd64/tubectl register-pid $! foo tcp 127.0.0.1 9999
# Send a message!
$ echo testing | nc -q 1 127.0.0.1 80
```

The real power is in the `bind` command. Some examples:

```sh
# Send HTTP traffic on a /24 to the foo label.
$ sudo ./bin/amd64/tubectl bind foo tcp 127.0.0.0/24 80
# Send TCP traffic on all ports of a specific IP to the foo label.
$ sudo ./bin/amd64/tubectl bind foo tcp 127.0.0.22 0
```

Testing
---

`tubular` requires some bleeding edge Linux features and therefore runs tests
in a VM. You will need QEMU and [virtme][2] installed.

```sh
$ make test
# Without the vm
$ go test -exec sudo ./...
```

[1]: https://en.wikipedia.org/wiki/Series_of_tubes
[2]: https://github.com/amluto/virtme/
