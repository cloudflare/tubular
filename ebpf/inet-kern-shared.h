#include <linux/types.h>

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

enum { REDIR_MAP,
       BIND_MAP,
       SRVNAME_MAP,
};
