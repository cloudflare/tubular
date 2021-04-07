package testutil

import (
	"github.com/google/go-cmp/cmp"
	"inet.af/netaddr"
)

func IPComparer() cmp.Option {
	return cmp.Comparer(func(x, y netaddr.IP) bool {
		return x == y
	})
}
