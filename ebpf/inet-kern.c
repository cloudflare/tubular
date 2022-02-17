#include <stddef.h>

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define MAX_SOCKETS (1024)
#define MAX_BINDINGS (1000000)

enum {
	AF_INET  = 2,
	AF_INET6 = 10,
};

typedef __u32 destination_id_t;

struct addr {
	__u32 prefixlen;
	__u8 protocol;
	__u16 port;
	struct ip {
		__u32 ip_as_w[4];
	} addr;
} __attribute__((packed));

struct binding {
	destination_id_t id;
	__u32 prefixlen;
};

struct destination_metrics {
	__u64 lookups;
	__u64 misses;
	__u64 errors__bad_socket;
};

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(key_size, sizeof(destination_id_t));
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, MAX_SOCKETS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct addr);
	__type(value, struct binding);
	__uint(max_entries, MAX_BINDINGS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} bindings SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, 0);
	__uint(value_size, 0);
	__uint(max_entries, MAX_SOCKETS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} destinations SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, destination_id_t);
	__type(value, struct destination_metrics);
	__uint(max_entries, MAX_SOCKETS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} destination_metrics SEC(".maps");

static inline void cleanup_sk(struct bpf_sock **sk)
{
	if (*sk != NULL) {
		bpf_sk_release(*sk);
	}
}

#define __cleanup_sk __attribute__((cleanup(cleanup_sk)))

static inline const struct binding *select_binding(const struct binding *bind, const struct binding *wildcard_bind)
{
	if (bind) {
		if (wildcard_bind && wildcard_bind->prefixlen > bind->prefixlen) {
			/* The wildcard is more specific. */
			return wildcard_bind;
		}

		/* The wildcard is as specific, or less specific. Prefer the
		 * non-wildcard.
		 */
		return bind;
	}

	/* There is no non-wildcard binding. Use the wildcard (which may be NULL). */
	return wildcard_bind;
}

SEC("sk_lookup/dispatcher")
int dispatcher(struct bpf_sk_lookup *ctx)
{
	/* /32 and /128 */
	struct ip laddr_full = {};
	if (ctx->family == AF_INET) {
		laddr_full.ip_as_w[2] = bpf_htonl(0x0000ffff);
		laddr_full.ip_as_w[3] = ctx->local_ip4;
	}
	if (ctx->family == AF_INET6) {
		laddr_full.ip_as_w[0] = ctx->local_ip6[0];
		laddr_full.ip_as_w[1] = ctx->local_ip6[1];
		laddr_full.ip_as_w[2] = ctx->local_ip6[2];
		laddr_full.ip_as_w[3] = ctx->local_ip6[3];
	}

	struct addr key = {
		.prefixlen = (sizeof(struct addr) - 4) * 8,
		.protocol  = ctx->protocol,
		.port      = ctx->local_port,
		.addr      = laddr_full,
	};

	/* First, find a binding with the port specified. */
	const struct binding *bind = bpf_map_lookup_elem(&bindings, &key);

	/* Second, find a wildcard port binding. */
	key.port                            = 0;
	const struct binding *wildcard_bind = bpf_map_lookup_elem(&bindings, &key);

	bind = select_binding(bind, wildcard_bind);
	if (!bind) {
		return SK_PASS;
	}

	struct destination_metrics *metrics = bpf_map_lookup_elem(&destination_metrics, &bind->id);
	if (!metrics) {
		/* Per-CPU arrays are fully pre-allocated, so a lookup failure here
		 * means that dest_id is out of bounds. Since we check that metrics
		 * and socket map have the same size, the socket lookup will also
		 * fail. Since there is no use in continuing, reject the packet.
		 */
		return SK_DROP;
	}

	metrics->lookups++;

	struct bpf_sock *sk __cleanup_sk = bpf_map_lookup_elem(&sockets, &bind->id);
	if (!sk) {
		/* Service for the address registered,
		 * but socket is missing (service
		 * down?). Drop connections so they
		 * don't end up in some other socket
		 * bound to the address/port reserved
		 * for this service.
		 */
		metrics->misses++;
		return SK_DROP;
	}

	int err = bpf_sk_assign(ctx, sk, 0);
	if (err) {
		/* Same as for no socket case above,
		 * except here socket is not compatible
		 * with the IP family or L4 transport
		 * for the address/port it is mapped
		 * to. Service misconfigured.
		 */
		metrics->errors__bad_socket++;
		return SK_DROP;
	}

	/* Found and selected a suitable socket. Direct
	 * the incoming connection to it. */
	return SK_PASS;
}

SEC("license") const char __license[] = "BSD-3-Clause";
