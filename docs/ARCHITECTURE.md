Architecture
===

tubular consists of a BPF program that attaches to the sk_lookup hook in the
kernel and userspace Go code which manages the BPF program. `tubectl` wraps
both with a CLI that is easy to distribute.

`tubectl` manages two kinds of objects: bindings and sockets. A binding
encodes a rule against which an incoming packet is matched. A socket is a reference
to a TCP or UDP socket that can accept new connections or packets.

Bindings and sockets are "glued" together via arbitrary strings called labels.
Conceptually, a binding assigns a label to some traffic. The label is then used
to find the correct socket.

![TCP 127.0.0.1:80 -(binding lookup)-> "foo" -(socket lookup)-> socket #XYZ](./packet-label-socket.svg)

To direct HTTP traffic destined for 127.0.0.1 to the label `foo` we use `tubectl bind`:

```
$ sudo tubectl bind "foo" tcp 127.0.0.1 80
```

Due to the flexibility of eBPF we can have much more powerful constructs than
the BSD API. For example, we can redirect connections to all IPs in
127.0.0.0/24:

```
$ sudo tubectl bind "bar" tcp 127.0.0.0/24 80
```

Alternatively, we could redirect all ports on a single IP:

```
$ sudo tubectl bind "baz" tcp 127.0.0.2 0
```

A side effect of this power is that it's possible to create bindings that "overlap":

```
1: tcp 127.0.0.1/32 80 -> "foo"
2: tcp 127.0.0.0/24 80 -> "bar"
```

The first binding says that HTTP traffic to localhost should go to `foo`, while
the second asserts that HTTP traffic in the localhost subnet should go to `bar`.
This creates a contradiction, which binding should we choose? tubular resolves
this by defining precedence rules for bindings:

1. A prefix with a longer mask is more specific, e.g. 127.0.0.1/32 wins over
   127.0.0.0/24.
2. A port is more specific than the port wildcard, e.g. port 80 wins
   over "all ports" (0).

Applying this to our example, HTTP traffic to all IPs in 127.0.0.0/24 will be
directed to `foo`, except for 127.0.0.1 which goes to `bar`.

## Getting a hold of sockets

sk_lookup needs a reference to a TCP or a UDP socket to redirect traffic to it.
However, a socket is usually accessible only by the process which created it
with the socket syscall. For example, an instance of an nginx serving HTTP
creates a TCP listening socket bound to port 80. To configure traffic redirection
with sk_lookup to the nginx listening socket we need gain access to it.

A fairly well known solution is to make processes cooperate by passing socket
file descriptors via [SCM_RIGHTS][] messages to a tubular daemon. That daemon can
then take the necessary steps to hook up the socket with sk_lookup. This approach
has several drawbacks:

1. Requires modifying processes to send SCM_RIGHTS
2. Requires a tubular daemon, which may crash

There is another way of getting at sockets by using systemd, provided
[socket activation][] is used. It works by creating an additional service unit
with the correct [Sockets][] setting.

```
[Unit]
Requisite=foo.socket

[Service]
Type=oneshot
Sockets=foo.socket
ExecStart=tubectl register "foo"
```

Since we can rely on systemd to execute `tubectl` at the correct times we don't
need a daemon any more. However, the reality is that a lot of popular software
doesn't use systemd socket activation, nginx included. Dealing with systemd sockets
is complicated and doesn't invite experimentation. Which brings us to the
final trick, [pidfd_getfd][]:

> The pidfd_getfd() system call allocates a new file descriptor in
> the calling process.  This new file descriptor is a duplicate of
> an existing file descriptor, targetfd, in the process referred to
> by the PID file descriptor pidfd.

We can use it to iterate all file descriptors of a process, and pick the socket we
are interested in. To return to our nginx example, we can use the following command
to find the TCP socket bound to 127.0.0.1 port 8080 in the nginx process and
register it under the "foo" label:

```
$ sudo tubectl register-pid $(pidof nginx) "foo" tcp 127.0.0.1 8080
```

It's easy to wire this up using systemd's [ExecStartPost][] if the need arises.

```
[Service]
Type=forking # or notify
ExecStart=/path/to/some/command
ExecStartPost=tubectl register-pid $MAINPID foo tcp 127.0.0.1 8080
```

## Managing and persisting state

tubular takes over functionality that has traditionally been
reserved to the OS's networking stack. This is very powerful but with that
power comes the requirement for robustness. The kernel might well start rejecting
connections if tubular were to crash. As a result, there is no persistent
daemon required to operate tubular. Instead tubectl is used to modify all
necessary state in [BPF key / value data structures also known as maps][maps],
which are persisted into a subdirectory of /sys/fs/bpf:

```
/sys/fs/bpf/4026532024_dispatcher
├── bindings
├── destination_metrics
├── destinations
├── sockets
└── ...
```

The way state is stored differs from what is exposed on the command line.
Labels are convenient for humans but they are of variable length. Dealing with
variable length data in BPF is cumbersome and slow, so the BPF program never
references labels at all. Instead, the user space code allocates fixed length
numeric IDs, which are then used in the BPF. Each ID represents a
`(label, domain, protocol)` tuple, internally called `destination`.

For example, adding a binding for `"foo" tcp 127.0.0.1 ...`
allocates an ID for `("foo", AF_INET, TCP)`. Including domain and protocol in the
destination allows a simpler data structures in the BPF.
Each allocation also tracks how many bindings reference a destination so that we
can recycle unused IDs. This data is persisted into the `destinations` hash table,
which is keyed by (Label, Domain, Protocol) and contains (ID, Count). Metrics for
each  destination are tracked in `destination_metrics`.

![Schema of destinations map](./destinations.svg)

`bindings` is a [longest prefix match (LPM) trie][trie] which stores a mapping from
`(protocol, port, prefix)` to `(ID, prefix length)`. The ID is used as a key to
the `sockets` map which contains pointers to kernel socket structures. IDs are
allocated in a way that makes them suitable as an array index, which allows
using the simpler BPF sockmap (an array) instead of a socket hash table.
The prefix length is duplicated in the value to work around shortcomings in
the BPF API.

![Schema of bindings and sockets map](./bindings-sockets.svg)

### Encoding precedence of bindings

As discussed, bindings have a precedence associated with them. To repeat the
earlier example:

```
1: tcp 127.0.0.1/32 80 -> "foo"
2: tcp 127.0.0.0/24 80 -> "bar"
```

The first binding should be matched before the second one. We need to encode this
in the BPF somehow. One idea is to generate some code that executes the bindings
in order of specificity:

```
1: if (ip/32 == 127.0.0.1) return "bar"
2: if (ip/24 == 127.0.0.0) return "foo"
...
```

This has the downside that the BPF gets longer the more bindings are added, which
slows down execution. It's also difficult to introspect and debug such long
programs. Instead we use an specialised BPF LPM trie map to do the hard work,
which can be inspected from user space via `bpftool` and which offers consistent
performance.

Using a trie requires requires a clever trick for encoding the precedence of bindings
into a key that we can look up. Here is a simplified version of this encoding,
which ignores IPv6 and uses labels instead of IDs.
To insert `tcp 127.0.0.0/24 80` we first convert the IP address into a number.

```
127.0.0.0 = 0x7f 00 00 00
```

Since we're only interested in the first 24 bits of the address we, can write
the whole prefix as

```
127.0.0.0/24 = 0x7f 00 00 ??
```

where `?` means that the value is not specified. We choose the number 0x01 to
represent TCP and prepend it and the port number to create the full key:

```
tcp 127.0.0.0/24 80 = 0x01 50 7f 00 00 ??
```

Converting `tcp 127.0.0.1/32 80` happens in exactly the same way. Once the
converted values are inserted into the trie, the LPM trie conceptually contains
the following keys and values.

```
LPM trie:
        0x01 50 7f 00 00 ?? = "foo"
        0x01 50 7f 00 00 01 = "bar"
```

To find the binding for a TCP packet destined for 127.0.0.1:80, we again encode
a key and perform a look up.

```
input:  0x01 50 7f 00 00 01   TCP packet to 127.0.0.1:80
---------------------------
LPM trie:
        0x01 50 7f 00 00 ?? = "foo"
           ✓  ✓  ✓  ✓  ✓
        0x01 50 7f 00 00 01 = "bar"
           ✓  ✓  ✓  ✓  ✓  ✓
---------------------------
result: "bar"

✓ = byte matches
```

The trie returns "bar" since its key shares the longest prefix with the input.
Note that we stop comparing keys once we reach unspecified `?` bytes. This
is important when looking up the binding for a TCP packet to 127.0.0.255:80.

```
input:  0x01 50 7f 00 00 ff   TCP packet to 127.0.0.255:80
---------------------------
LPM trie:
        0x01 50 7f 00 00 ?? = "foo"
           ✓  ✓  ✓  ✓  ✓
        0x01 50 7f 00 00 01 = "bar"
           ✓  ✓  ✓  ✓  ✓  ⨯
---------------------------
result: "foo"

⨯ = byte doesn't match
```

In this case "bar" is discarded since the last byte doesn't match the input.
"foo" is returned since its last byte is unspecified and therefore considered
to be a valid match.

### Read-only access with minimal privileges

Linux has the powerful `ss` tool (part of iproute2) available to inspect socket state:

```
$ ss -tl src 127.0.0.1
State      Recv-Q      Send-Q           Local Address:Port           Peer Address:Port
LISTEN     0           128                  127.0.0.1:ipp                 0.0.0.0:*
```

With tubular in the picture this output is not accurate any more. `tubectl bindings`
makes up for this shortcoming:

```
$ sudo tubectl bindings tcp 127.0.0.1
Bindings:
 protocol       prefix port label
      tcp 127.0.0.1/32   80   foo
```

Running this command requires super-user privileges, despite being safe for any
user to run. While this is acceptable for casual inspection by a human operator,
it's a deal breaker for observability via pull-based systems like Prometheus.
The usual approach is to expose metrics via a HTTP server, which would have to
run with elevated privileges and be accessible remotely. Instead, BPF gives us
the tools to enable read-only access to tubular state with minimal privileges.

The key is to carefully set file ownership and mode for state in /sys/fs/bpf.
Creating and opening files in /sys/fs/bpf uses [BPF_OBJ_PIN and BPF_OBJ_GET][obj pinning].
Calling BPF_OBJ_GET with BPF_F_RDONLY is roughly equivalent to open(O_RDONLY)
and allows accessing state in a read-only fashion, provided the file permissions
are correct. tubular gives the owner full access but restricts read-only access
to the group:

```
$ sudo ls -l /sys/fs/bpf/4026532024_dispatcher | head -n 3
total 0
-rw-r----- 1 root root 0 Feb  2 13:19 bindings
-rw-r----- 1 root root 0 Feb  2 13:19 destination_metrics
```

It's easy to choose which user and group should own state when loading tubular:

```
$ sudo -u root -g tubular tubectl load
created dispatcher in /sys/fs/bpf/4026532024_dispatcher
loaded dispatcher into /proc/self/ns/net
$ sudo ls -l /sys/fs/bpf/4026532024_dispatcher | head -n 3
total 0
-rw-r----- 1 root tubular 0 Feb  2 13:42 bindings
-rw-r----- 1 root tubular 0 Feb  2 13:42 destination_metrics
```

There is one more obstacle, [systemd mounts /sys/fs/bpf][systemd bpffs]
in a way that makes it inaccessible to anyone but root. Adding the executable
bit to the directory fixes this.

```
$ sudo chmod -v o+x /sys/fs/bpf
mode of '/sys/fs/bpf' changed from 0700 (rwx------) to 0701 (rwx-----x)
```

Finally, we can export metrics without privileges:

```
$ sudo -u nobody -g tubular tubectl metrics 127.0.0.1 8080
Listening on 127.0.0.1:8080
^C
```

There is a caveat, unfortunately: truly unprivileged access requires unprivileged
BPF to be enabled. Many distros have taken to disabling it via the `unprivileged_bpf_disabled` sysctl, and so in practice scraping metrics does
require CAP_BPF.

## Updating the BPF program

tubular is distributed as a single binary, but really consists of two
pieces of code with widely differing lifetimes. The BPF program is loaded into
the kernel once and then may be active for weeks or months, until it is explicitly
replaced. Like maps, the program (and link, see below) is persisted into /sys/fs/bpf:

```
/sys/fs/bpf/4026532024_dispatcher
├── link
├── program
└── ...
```

The user space code is executed for seconds at a time and is replaced whenever
the binary on disk changes. This means that user space has to be able to deal
with an "old" BPF program in the kernel somehow. The simplest way to achieve
this is to compare what is loaded into the kernel with the BPF shipped as
part of `tubectl`. If the two don't match we return an error:

```
$ sudo tubectl bind foo tcp 127.0.0.1 80
Error: bind: can't open dispatcher: loaded program #158 has differing tag: "938c70b5a8956ff2" doesn't match "e007bfbbf37171f0"
```

`tag` is the truncated hash of the instructions making up a BPF program, which
the kernel makes available for every loaded program:

```
$ sudo bpftool prog list id 158
158: sk_lookup  name dispatcher  tag 938c70b5a8956ff2
...
```

Of course, just returning an error isn't enough. There needs to be a way to
update the kernel program so that it's once again safe to make changes. This is
where the `link` comes into play. bpf_links are used to attach programs to the
[sk_lookup hook][sk_lookup]. "Enabling" a BPF program is a two step process:
first, load the BPF program, next attach it to a hook using a bpf_link. Afterwards
the program will execute the next time the hook is executed. By updating the
link we can change the program on the fly.

```
$ sudo tubectl upgrade
Upgraded dispatcher to 2022.1.0-dev, program ID #159
$ sudo bpftool prog list id 159
159: sk_lookup  name dispatcher  tag e007bfbbf37171f0
...
$ sudo tubectl bind foo tcp 127.0.0.1 80
bound foo#tcp:[127.0.0.1/32]:80
```

[maps]: https://prototype-kernel.readthedocs.io/en/latest/bpf/ebpf_maps.html
[trie]: https://en.wikipedia.org/wiki/Trie
[ip prefix]: https://networkengineering.stackexchange.com/a/3873
[l4drop]: https://blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations/
[sk_lookup]: https://www.kernel.org/doc/html/latest/bpf/prog_sk_lookup.html#attachment
[obj pinning]: https://www.kernel.org/doc/html/latest/userspace-api/ebpf/syscall.html#bpf-subcommand-reference
[systemd bpffs]: https://github.com/systemd/systemd/blob/b049b48c4b6e60c3cbec9d2884f90fd4e7013219/src/shared/mount-setup.c#L111-L112
[SCM_RIGHTS]: https://blog.cloudflare.com/know-your-scm_rights/
[unix sockets]: https://www.man7.org/linux/man-pages/man7/unix.7.html
[socket activation]: https://www.freedesktop.org/software/systemd/man/systemd.socket.html
[ExecStartPost]: https://www.freedesktop.org/software/systemd/man/systemd.service.html#ExecStartPre=
[Sockets]: https://www.freedesktop.org/software/systemd/man/systemd.service.html#Sockets=
[pidfd_getfd]: https://www.man7.org/linux/man-pages/man2/pidfd_getfd.2.html