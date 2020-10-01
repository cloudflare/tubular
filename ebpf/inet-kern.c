#include <stddef.h>

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define MAX_SOCKETS (1024)

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

struct destination_metrics {
	__u64 received_packets;
	__u64 dropped_packets__missing_socket;
	__u64 dropped_packets__incompatible_socket;
};

struct bpf_map_def SEC("maps") sockets = {
	.type        = BPF_MAP_TYPE_SOCKMAP,
	.max_entries = MAX_SOCKETS,
	.key_size    = sizeof(destination_id_t),
	.value_size  = sizeof(__u64),
};

struct bpf_map_def SEC("maps") bindings = {
	.type        = BPF_MAP_TYPE_LPM_TRIE,
	.max_entries = 4096,
	.key_size    = sizeof(struct addr),
	.value_size  = sizeof(destination_id_t),
	.map_flags   = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") destination_metrics = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.max_entries = MAX_SOCKETS,
	.key_size    = sizeof(destination_id_t),
	.value_size  = sizeof(struct destination_metrics),
};

static inline void cleanup_sk(struct bpf_sock **sk)
{
	if (*sk != NULL) {
		bpf_sk_release(*sk);
	}
}

#define __cleanup_sk __attribute__((cleanup(cleanup_sk)))

SEC("license") const char __license[] = "Proprietary";

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

	struct addr lookup_keys[] = {
		{
			.prefixlen = (sizeof(struct addr) - 4) * 8,
			.protocol  = ctx->protocol,
			.port      = ctx->local_port,
			.addr      = laddr_full,
		},
		{
			.prefixlen = (sizeof(struct addr) - 4) * 8,
			.protocol  = ctx->protocol,
			.port      = 0,
			.addr      = laddr_full,
		},
	};

#pragma clang loop unroll(full)
	for (int i = 0; i < (int)ARRAY_SIZE(lookup_keys); i++) {
		__u32 *dest_id = bpf_map_lookup_elem(&bindings, &lookup_keys[i]);
		if (!dest_id) {
			continue;
		}

		struct destination_metrics *metrics = bpf_map_lookup_elem(&destination_metrics, dest_id);
		if (!metrics) {
			/* Per-CPU arrays are fully pre-allocated, so a lookup failure here
			 * means that dest_id is out of bounds. Since we check that metrics
			 * and socket map have the same size, the socket lookup will also
			 * fail. Since there is no use in continuing, reject the packet.
			 */
			return SK_DROP;
		}

		metrics->received_packets++;

		struct bpf_sock *sk __cleanup_sk = bpf_map_lookup_elem(&sockets, dest_id);
		if (!sk) {
			/* Service for the address registered,
			 * but socket is missing (service
			 * down?). Drop connections so they
			 * don't end up in some other socket
			 * bound to the address/port reserved
			 * for this service.
			 */
			metrics->dropped_packets__missing_socket++;
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
			metrics->dropped_packets__incompatible_socket++;
			return SK_DROP;
		}

		/* Found and selected a suitable socket. Direct
		 * the incoming connection to it. */
		return SK_PASS;
	}

	return SK_PASS;
}
