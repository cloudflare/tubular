tubular
===

The control plane for BPF socket lookup. Steers traffic that arrives via the
[tubes of the Internet][1] to processes running on the machine. Its much more
flexible than traditional BSD `bind` semantics:

* You can bind to all ports on an IP
* You can bind to a subnet instead of an IP
* You can bind to all ports on a subnet

Testing
---

`tubular` requires some bleeding edge Linux features and provides a script that
automatically fetches an appropriate kernel:

```
$ ./run-tests.sh
```

You will need QEMU and [virtme][2] installed, and probably be on the VPN.

[1]: https://en.wikipedia.org/wiki/Series_of_tubes
[2]: https://github.com/amluto/virtme/
