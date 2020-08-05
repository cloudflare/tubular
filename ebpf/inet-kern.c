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

struct addr {
	__u32 prefixlen;
	__u8 protocol;
	__u16 port;
	struct ip {
		__u32 ip_as_w[4];
	} addr;
};

/* FD names passed by systemd can be 255 characters long. Match the limit. */
struct srvname {
	char name[255];
};

enum {
	REDIR_MAP,
	BIND_MAP,
	SRVNAME_MAP,
};

struct bpf_map_def SEC("maps") redir_map = {
	.type        = BPF_MAP_TYPE_SOCKMAP,
	.max_entries = 512,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u64),
};

struct bpf_map_def SEC("maps") bind_map = {
	.type        = BPF_MAP_TYPE_LPM_TRIE,
	.max_entries = 4096,
	.key_size    = sizeof(struct addr),
	.value_size  = sizeof(struct srvname),
	.map_flags   = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") srvname_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.max_entries = 512,
	.key_size    = sizeof(struct srvname),
	.value_size  = sizeof(__u32),
	.map_flags   = BPF_F_NO_PREALLOC,
};

SEC("license") const char __license[] = "Proprietary";

SEC("sk_lookup/dispatcher")
int dispatcher(struct bpf_sk_lookup *ctx)
{
	/* Force 32 bit loads from context, to avoid eBPF "ctx modified"
	 * messages */
	volatile __u32 protocol   = ctx->protocol;
	volatile __u32 local_port = ctx->local_port;

	/* /32 and /128 */
	struct ip laddr_full = {};
	if (ctx->family == AF_INET) {
		laddr_full.ip_as_w[2] = bpf_htonl(0x0000ffff);
		laddr_full.ip_as_w[3] = ctx->local_ip4;
	}
	if (ctx->family == AF_INET6) {
		/* eBPF voodoo. Must be unordered otherwise some
		 * optimization breaks the generated bpf. */
		laddr_full.ip_as_w[3] = ctx->local_ip6[3];
		laddr_full.ip_as_w[0] = ctx->local_ip6[0];
		laddr_full.ip_as_w[1] = ctx->local_ip6[1];
		laddr_full.ip_as_w[2] = ctx->local_ip6[2];
	}

	struct addr lookup_keys[] = {
		{
			.protocol = protocol,
			.port     = local_port,
			.addr     = laddr_full,
		},
		{
			.protocol = protocol,
			.port     = 0,
			.addr     = laddr_full,
		},
	};

	int i = 0;
#pragma clang loop unroll(full)
	for (i = 0; i < (int)ARRAY_SIZE(lookup_keys); i++) {
		struct srvname *srvname = NULL;
		/* eBPF voodoo. For some reason key = lookup_keys[i] aint work.
		 */
		struct addr key = {
			.protocol = lookup_keys[i].protocol,
			.port     = lookup_keys[i].port,
		};
		key.prefixlen = (sizeof(struct addr) - 4) * 8;
		key.addr      = lookup_keys[i].addr;

		srvname = (struct srvname *)bpf_map_lookup_elem(&bind_map, &key);
		if (srvname != NULL) {
			__u32 *index = (__u32 *)bpf_map_lookup_elem(&srvname_map, srvname);
			if (index != NULL) {
				struct bpf_sock *sk = bpf_map_lookup_elem(&redir_map, index);
				if (!sk) {
					/* Service for the address registered,
					 * but socket is missing (service
					 * down?). Drop connections so they
					 * don't end up in some other socket
					 * bound to the address/port reserved
					 * for this service.
					 */
					return BPF_DROP;
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
					return BPF_DROP;
				}

				/* Found and selected a suitable socket. Direct
				 * the incoming connection to it. */
				bpf_sk_release(sk);
				return BPF_REDIRECT;
			}
		}
	}
	return BPF_OK;
}
