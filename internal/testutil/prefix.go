package testutil

import (
	"github.com/google/go-cmp/cmp"
	"inet.af/netaddr"
)

func IPPrefixComparer() cmp.Option {
	return cmp.Comparer(func(x, y netaddr.IPPrefix) bool {
		return x == y
	})
}
