struct bpf_map_def SEC("maps") redir_map = {
	.type = BPF_MAP_TYPE_SOCKMAP,
	.max_entries = 512,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
};

struct bpf_map_def SEC("maps") bind_map = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.max_entries = 4096,
	.key_size = sizeof(struct addr),
	.value_size = sizeof(struct srvname),
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") srvname_map = {
	.type = BPF_MAP_TYPE_HASH,
	.max_entries = 512,
	.key_size = sizeof(struct srvname),
	.value_size = sizeof(__u32),
	.map_flags = BPF_F_NO_PREALLOC,
};
