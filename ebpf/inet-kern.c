#include <stddef.h>

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

enum {
	AF_INET  = 2,
	AF_INET6 = 10,
};

typedef __u64 label_id_t;

struct addr {
	__u32 prefixlen;
	__u8 protocol;
	__u16 port;
	struct ip {
		__u32 ip_as_w[4];
	} addr;
} __attribute__((packed));

struct destination_key {
	__u8 l3_proto;
	__u8 l4_proto;
	label_id_t label_id;
} __attribute__((packed));

struct bpf_map_def SEC("maps") destinations = {
	.type        = BPF_MAP_TYPE_SOCKHASH,
	.max_entries = 512,
	.key_size    = sizeof(struct destination_key),
	.value_size  = sizeof(__u64),
};

struct bpf_map_def SEC("maps") bindings = {
	.type        = BPF_MAP_TYPE_LPM_TRIE,
	.max_entries = 4096,
	.key_size    = sizeof(struct addr),
	.value_size  = sizeof(label_id_t),
	.map_flags   = BPF_F_NO_PREALLOC,
};

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
			.protocol = ctx->protocol,
			.port     = ctx->local_port,
			.addr     = laddr_full,
		},
		{
			.protocol = ctx->protocol,
			.port     = 0,
			.addr     = laddr_full,
		},
	};

	int i = 0;
#pragma clang loop unroll(full)
	for (i = 0; i < (int)ARRAY_SIZE(lookup_keys); i++) {
		/* eBPF voodoo. For some reason key = lookup_keys[i] aint work.
		 */
		struct addr key = {
			.protocol = lookup_keys[i].protocol,
			.port     = lookup_keys[i].port,
		};
		key.prefixlen = (sizeof(struct addr) - 4) * 8;
		key.addr      = lookup_keys[i].addr;

		label_id_t *label_id = bpf_map_lookup_elem(&bindings, &key);
		if (!label_id) {
			continue;
		}

		struct destination_key dst_key = {
			.l3_proto = ctx->family,
			.l4_proto = ctx->protocol,
			.label_id = *label_id,
		};
		struct bpf_sock *sk = bpf_map_lookup_elem(&destinations, &dst_key);
		if (!sk) {
			/* Service for the address registered,
			 * but socket is missing (service
			 * down?). Drop connections so they
			 * don't end up in some other socket
			 * bound to the address/port reserved
			 * for this service.
			 */
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
			bpf_sk_release(sk);
			return SK_DROP;
		}

		/* Found and selected a suitable socket. Direct
		 * the incoming connection to it. */
		bpf_sk_release(sk);
		return SK_PASS;
	}

	return SK_PASS;
}
